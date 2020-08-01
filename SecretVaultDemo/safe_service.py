from flask import Flask
from secret_vault import SecretVault


try:
    sv = SecretVault('127.0.0.1:3333', './api_key.key')
except Exception as e:
    print(e)
    exit(1)

secret = sv.get_secret('test_secret')
app = Flask(__name__)


@app.route("/")
def hello():
    return f'Hello World! Service is UP!! \n Secret: {secret}'


if __name__ == '__main__':
    app.run(port=2222)
