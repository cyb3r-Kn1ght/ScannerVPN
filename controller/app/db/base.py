# app/db/base.py
from sqlalchemy.ext.declarative import declarative_base

# Base class mà tất cả các model SQLAlchemy sẽ kế thừa
Base = declarative_base()