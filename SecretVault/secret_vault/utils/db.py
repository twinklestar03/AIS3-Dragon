import logging
import threading
import shutil
from urllib.parse import urlparse
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from secret_vault.models import *

__all__ = ['DB']

logger = logging.getLogger(__name__)


class DB:
    def __init__(self, conn_str):
        # Parse connection string
        uri = urlparse(conn_str)
        self.db_scheme = uri.scheme
        self.db_path = uri.path.lstrip('/')
        # Connect
        self.engine = create_engine(conn_str, connect_args={'timeout': 60, 'check_same_thread': False})

        # from: https://stackoverflow.com/questions/1654857/nested-transactions-with-sqlalchemy-and-sqlite
        if self.db_scheme == 'sqlite':

            @event.listens_for(self.engine, 'connect')
            def do_connect(dbapi_connection, connection_record):
                # disable pysqlite's emitting of the BEGIN statement entirely.
                # also stops it from emitting COMMIT before any DDL.
                dbapi_connection.isolation_level = None

            @event.listens_for(self.engine, 'begin')
            def do_begin(conn):
                # emit our own BEGIN
                conn.execute('BEGIN EXCLUSIVE')

        self._session = sessionmaker(bind=self.engine)
        
        Base.metadata.create_all(self.engine)

        # For session scoping
        self.tls = threading.local()

    @contextmanager
    def session(self, *args, **kwargs):
        if not hasattr(self.tls, 'db_session') or not self.tls.db_session:
            kwargs['expire_on_commit'] = False
            self.tls.db_session = self._session(*args, **kwargs)
            try:
                yield self.tls.db_session
                self.tls.db_session.commit()
            except:
                self.tls.db_session.rollback()
                raise
            finally:
                self.tls.db_session.close()
                self.tls.db_session = None
        else:
            yield self.tls.db_session

    def backup(self, path):
        if self.db_scheme == 'sqlite':
            shutil.copyfile(self.db_path, path)

    def close(self):
        self.engine.dispose()
