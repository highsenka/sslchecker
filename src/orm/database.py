from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from src.settings.database import database_settings
from contextlib import contextmanager

from sqlalchemy.exc import OperationalError, StatementError
from sqlalchemy.orm.query import Query as _Query
from time import sleep

SQLALCHEMY_DATABASE_URL = database_settings.full_url_sync

# engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=True)
engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_size=10, max_overflow=20, pool_recycle=300, pool_pre_ping=True, pool_use_lifo=True)

class RetryingQuery(_Query):
    __max_retry_count__ = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __iter__(self):
        attempts = 0
        while True:
            attempts += 1
            try:
                return super().__iter__()
            except OperationalError as ex:
                if "server closed the connection unexpectedly" not in str(ex):
                    raise
                if attempts <= self.__max_retry_count__:
                    sleep_for = 2 ** (attempts - 1)
                    sleep(sleep_for)
                    continue
                else:
                    raise
            except StatementError as ex:
                if "reconnect until invalid transaction is rolled back" not in str(ex):
                    raise
                self.session.rollback()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, query_cls=RetryingQuery)

Base = declarative_base()

# models.Base.metadata.create_all(bind=engine)
# Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_context = contextmanager(get_db)
