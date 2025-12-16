from sqlalchemy import Column, Integer, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class User(Base):
    __tablename__ = "Users"

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(Text, nullable=False, index=True)
    hashed_password = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

class Refresh_Token(Base):
    __tablename__ = "Refresh_Tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.user_id", ondelete="CASCADE"), 
        nullable=False
        )
    token_hash = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean)
    created_at = Column(DateTime, server_default=func.now())