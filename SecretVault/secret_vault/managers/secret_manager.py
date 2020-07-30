import logging

__all__ = ['SecretManager']


class SecretManager:
    @classmethod
    def initialize(cls, db_session):
        cls.db_session = db_session
        cls.secrets_cache = []
        cls.users_cache = []

    @classmethod
    def is_valid_secret(cls, secret_name):
        # Validate the given string is a secret name
        pass

    @classmethod
    def is_accessible(cls, secret_name, access_token):
        # Check the token scope
        pass

    @classmethod
    def get_secret(cls, secret_name, access_token):
        # If the access token has privilege to access the secret
        pass
