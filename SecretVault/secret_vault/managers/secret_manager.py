import logging
from secret_vault.models import Secret

__all__ = ['SecretManager']


class SecretManager:
    @classmethod
    def initialize(cls, db):
        cls.db = db
        cls.secrets_cache = []
        cls.users_cache = []

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
    def is_accessible(cls, secret_name, **kwargs):
        if not kwargs['access_token']:
            return False
        # Check the token scope
        return True

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
