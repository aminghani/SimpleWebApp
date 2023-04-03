from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

info = {
    "password": os.environ.get("POSTGRES_PASSWORD")
}
SQLALCHEMY_DATABASE_URL = f"postgresql://postgres:{info['password']}@localhost/simpleWebApp"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()