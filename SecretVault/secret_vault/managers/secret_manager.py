import logging
import hashlib
from datetime import datetime
from secret_vault.models import Secret

__all__ = ['SecretManager']


class SecretManager:
    @classmethod
    def initialize(cls, db):
        cls.db = db
        cls.secrets_hash_cache = []
        cls.users_cache = []
        cls.warning_entries = {}

        cls._gen_all_secret_hash()

    @classmethod
    def _gen_all_secret_hash(cls):
        all_secret = []
        hs = []
        with cls.db.session() as db:
            all_secret = Secret.get_all(db)

        try:
            for secret in all_secret:
                h = hashlib.sha256(str(secret.secret_data).encode()) 
                hs.append(h.hexdigest())
        except:
            return

        cls.secrets_hash_cache = hs
        print(hs)

    @classmethod
    def get_all_secrets_name(cls, **kwargs):
        with cls.db.session() as db:
            secret_names = []

            for e in Secret.get_all(db):
                secret_names.append(e.secret_name)
            return secret_names

    @classmethod
    def is_valid_secret(cls, secret_name, **kwargs):
        # Validate the given string is a secret name
        with cls.db.session() as db:
            if not Secret.get_by_name(db, secret_name) is None:
                return True
            else:
                return False

    @classmethod
    def get_secret(cls, secret_name, **kwargs):
        # If the access token has privilege to access the secret
        with cls.db.session() as db:
            secret = Secret.get_by_name(db, secret_name)
            return secret.secret_data

    @classmethod
    def create_secret(cls, secret_name, secret_data, **kwargs):
        with cls.db.session() as db:
            if Secret.create(db, secret_name, secret_data):
                cls._gen_all_secret_hash()
                return True
            
            else:
                return False

    @classmethod
    def delete_secret(cls, secret_name, **kwargs):
        with cls.db.session() as db:
            if Secret.delete(db, secret_name):
                return True
            
            else:
                return False

    @classmethod
    def can_create(cls, access_token=''):
        return True

    @classmethod
    def can_delete(cls, access_token=''):
        return True

    @classmethod
    def is_accessible(cls, secret_name, **kwargs):
        if not kwargs['access_token']:
            return False
        # Check the token scope
        return True

    @classmethod
    def is_exposed(cls, secret_hash, filename, n_line, **kwargs):
        if secret_hash in cls.secrets_hash_cache:

            warning_entry = cls.warning_entries.get(filename, dict())
            warning_entry['filename'] = filename

            # Prevent duplicate entries of lines 
            if warning_entry.get('date', None) is not None:
                datetime_obj = datetime.strptime(warning_entry['date'], '%Y-%m-%d %H:%M:%S.%f')

                if (datetime.now() - datetime_obj).seconds > 10:
                    warning_entry['lines'] = list()

            lines = warning_entry.get('lines', list())
            lines.append(n_line)
            warning_entry['lines'] = lines
            warning_entry['date'] = str(datetime.now())

            cls.warning_entries[filename] = warning_entry
            
            print(cls.warning_entries)
            return True

        return False

    @classmethod
    def get_exposed_datas(cls):
        return cls.warning_entries