from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from .base import *

__all__ = ['User']

class User(Base):
    def __init__(self, uname, passwd):
        self.username = uname
        self.password = passwd

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(20))
    password = Column(String(50))
    
    secrets = relationship('Secret')

    @staticmethod
    def create(db_session, uname, passwd, secrets=[]):
        user = User(uname, passwd)

        print(secrets)
        for s in secrets:
            user.secrets.append(s)

        return db_session.merge(user)

    @staticmethod
    def get_available_secrets_by_username(db_session, uname):
        user =  db_session.query(User).filter(User.username == uname).first()
        return user.secrets