from flask import Flask
from secret_vault.apis import GetSecretAPI
from secret_vault.models import Secret
from secret_vault.utils import DB


class SecretVault(object):
    def __init__(self, port, conn_str):
        self.app = Flask('__main__')
        self.db = DB(conn_str)
        self.port = port
        self._add_all_rules()

        with self.db.session() as db_session:
            Secret.create(db_session, 'Test_Secret', 'I\'m a Secret!')

    def _add_all_rules(self):
        self.app.add_url_rule('/get_secret/<string:secret_name>', view_func=GetSecretAPI.as_view('get_secret_api'))

    def run(self):
        self.app.run(port=self.port)

