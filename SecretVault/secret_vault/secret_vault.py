from flask import Flask
from secret_vault.apis import GetSecretAPI, CreateSecretAPI, ListSecretAPI, DeleteSecretAPI
from secret_vault.managers import AuthManager, SecretManager
from secret_vault.models import Secret, User
from secret_vault.utils import DB


class SecretVault(object):
    def __init__(self, port, conn_str):
        self.app = Flask('__main__')
        self.db = DB(conn_str)
        self.port = port
        self._add_all_rules()

        AuthManager.initialize(self.db)
        SecretManager.initialize(self.db)

    def _add_all_rules(self):
        self.app.add_url_rule('/get_secret/<string:secret_name>', view_func=GetSecretAPI.as_view('get_secret_api'))
        self.app.add_url_rule('/list_secrets', view_func=ListSecretAPI.as_view('list_secret_api'))
        self.app.add_url_rule('/create_secret', view_func=CreateSecretAPI.as_view('create_secret_api'))
        self.app.add_url_rule('/delete_secret/<string:secret_name>', view_func=DeleteSecretAPI.as_view('delete_secret_api'))

    def run(self):
        self.app.run(port=self.port)

