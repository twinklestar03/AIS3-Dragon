import logging
from secret_vault.models import User

__all__ = ['AuthManager']


class AuthManager:
    @classmethod
    def initialize(cls, db):
        cls.db = db

