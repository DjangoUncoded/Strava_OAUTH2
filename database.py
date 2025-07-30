import os
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///:memory:"  # fallback

engine = create_engine(DATABASE_URL)
Session_Local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
