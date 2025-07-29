
from dotenv import load_dotenv
load_dotenv()
import os
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
URL=os.getenv('DATABASE_URL')
engine=create_engine(URL)
Session_Local=sessionmaker(autocommit=False,autoflush=False,bind=engine)
Base = declarative_base()