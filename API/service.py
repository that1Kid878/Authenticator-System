from dotenv import load_dotenv
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from fastapi import Depends
from typing import Annotated

#Database
load_dotenv()
DB = os.getenv("Database_URL")
engine = create_engine(DB)
SessionLocal = sessionmaker(autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
db_dependency = Annotated[Session, Depends(get_db)]