from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from .base import *

__all__ = ['User']

class User(Base):
    # 表的名字:
    __tablename__ = 'users'

    # 表的结构:
    id = Column(Integer, primary_key=True)
    username = Column(String(20))
    password = Column(String(50))
    
    secrets_id = Column(Integer, ForeignKey('secrets.id'))
    secrets = relationship('Secret', back_populates='users')
    # accessiable_secrets = relationship('Secret')
