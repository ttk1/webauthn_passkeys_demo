import os
import json
import base64
import hashlib
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from flask import Flask, request, jsonify, session, render_template

app = Flask(__name__)
app.secret_key = os.urandom(32)
user_db = {}


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def base64url_decode(data):
    padding = "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_challenge():
    return base64url_encode(os.urandom(32))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/webauthn/register-challenge", methods=["POST"])
def register_challenge():
    data = request.json
    username = data.get("username")
    display_name = data.get("displayName")

    if not username or not display_name:
        return jsonify({"error": "Invalid request"}), 400

    user_id = hashlib.sha256(username.encode()).digest()
    user_db[username] = {"id": user_id, "displayName": display_name, "credentials": []}

    challenge = generate_challenge()
    session["challenge"] = challenge
    session["username"] = username

    return jsonify(
        {
            "challenge": challenge,
            "userId": base64url_encode(user_id),
            "username": username,
            "displayName": display_name,
        }
    )


@app.route("/webauthn/register", methods=["POST"])
def register():
    data = request.json
    username = session.get("username")
    challenge = session.get("challenge")

    if not username or not challenge:
        return jsonify({"error": "Session expired or invalid"}), 400

    user = user_db.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # チャレンジの検証
    client_data_json = base64url_decode(data["response"]["clientDataJSON"])
    client_data = json.loads(client_data_json.decode("utf-8"))
    if client_data.get("challenge") != challenge:
        return jsonify({"error": "Invalid challenge"}), 400

    # attestation の検証は省略

    credential = {
        "id": data["id"],
        "rawId": data["rawId"],
        "type": data["type"],
        "attestationObject": data["response"]["attestationObject"],
        "clientDataJSON": data["response"]["clientDataJSON"],
    }
    user["credentials"].append(credential)

    return jsonify({"success": True, "message": "Registration successful"})


@app.route("/webauthn/authenticate-challenge", methods=["POST"])
def authenticate_challenge():
    data = request.json
    username = data.get("username")

    user = user_db.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    challenge = generate_challenge()
    session["challenge"] = challenge
    session["username"] = username

    return jsonify(
        {
            "challenge": challenge,
            "allowCredentials": [
                {"id": cred["id"], "type": "public-key"} for cred in user["credentials"]
            ],
        }
    )


@app.route("/webauthn/authenticate", methods=["POST"])
def authenticate():
    data = request.json
    username = session.get("username")
    challenge = session.get("challenge")

    if not username or not challenge:
        return jsonify({"error": "Session expired or invalid"}), 400

    user = user_db.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    client_data_json = base64url_decode(data["response"]["clientDataJSON"])
    client_data = json.loads(client_data_json.decode("utf-8"))
    signature = base64url_decode(data["response"]["signature"])
    authenticator_data = base64url_decode(data["response"]["authenticatorData"])

    # チャレンジが一致するか検証
    if client_data.get("challenge") != challenge:
        return jsonify({"error": "Invalid challenge"}), 400

    # 署名対象データ
    signed_data = authenticator_data + hashlib.sha256(client_data_json).digest()

    # 公開鍵の取り出し
    credentials = list(
        filter(lambda cred: cred["id"] == data["id"], user["credentials"])
    )

    if not credentials:
        return jsonify({"error": "Credential not found"}), 404

    attestation_data = cbor2.loads(
        base64url_decode(credentials[0]["attestationObject"])
    )
    auth_data = attestation_data["authData"]
    credential_data_start = 37
    credential_id_length = int.from_bytes(
        auth_data[credential_data_start + 16 : credential_data_start + 18],
        byteorder="big",
    )
    credential_public_key_cbor = auth_data[
        credential_data_start + 18 + credential_id_length :
    ]
    credential_public_key = cbor2.loads(credential_public_key_cbor)
    try:
        # 署名の検証
        if credential_public_key[1] == 2:
            # EC2
            r, s = decode_dss_signature(signature)
            der_signature = encode_dss_signature(r, s)
            x = int.from_bytes(credential_public_key[-2], byteorder="big")
            y = int.from_bytes(credential_public_key[-3], byteorder="big")
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
            public_key = public_numbers.public_key()
            public_key.verify(der_signature, signed_data, ec.ECDSA(hashes.SHA256()))
        elif credential_public_key[1] == 3:
            # RSA
            n = int.from_bytes(credential_public_key[-1], byteorder="big")
            e = int.from_bytes(credential_public_key[-2], byteorder="big")
            public_numbers = rsa.RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key()
            public_key.verify(
                signature, signed_data, padding.PKCS1v15(), hashes.SHA256()
            )
        else:
            return jsonify({"error": "Invalid key type"}), 400
    except:
        return jsonify({"error": "Invalid signature"}), 400
    return jsonify({"success": True, "message": "Authentication successful"})
