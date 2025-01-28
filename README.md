# パスキー向けの WebAuthn デモアプリ

パスキーの勉強用に作ったものです。<br>
動作確認が目的で実用を想定した物ではありません。

### Requirements

* Python 3
  * 3.10 で動作確認しています
* Pipenv

### インストール

```sh
pipenv install
```

### アプリ起動コマンド

```sh
FLASK_RUN_HOST=127.0.0.1 FLASK_RUN_PORT=9999 FLASK_DEBUG=True FLASK_APP=demo/app.py pipenv run flask run
```

※環境変数は適宜変更してください
