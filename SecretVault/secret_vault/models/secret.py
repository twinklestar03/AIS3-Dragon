from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from .base import *

__all__ = ['Secret']


class Secret(Base):
    def __init__(self, secret_name, secret_data):
        self.secret_name = secret_name
        self.secret_data = secret_data

    __tablename__ = 'secrets'

    id = Column(Integer, primary_key=True)
    secret_name = Column(String(20))
    secret_data = Column(String(50))
    
    user_id = Column(Integer, ForeignKey('users.id'))

    @staticmethod
    def create(db_session, secret_name, secret_data):
        secret = Secret(secret_name, secret_data)

        return db_session.merge(secret)

    @staticmethod
    def get_by_name(db_session, secret_name):
        try:
            return db_session.query(Secret).filter(Secret.secret_name == secret_name).first()
        
        except:
            return None