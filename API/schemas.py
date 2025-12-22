from datetime import datetime, timezone
from sqlalchemy import Column, UUID, Text, Boolean, DateTime, ForeignKey, Integer
from sqlalchemy.orm import declarative_base
from pydantic import BaseModel, Field

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(Text, nullable=False, index=True)
    hashed_password = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))


class Refresh_Token(Base):
    __tablename__ = "refresh_tokens"

    token_id = Column(UUID(as_uuid=True), primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    token_hash = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))


class LoginRequest(BaseModel):
    username: str
    password: str = Field(
        min_length=12,
        max_length=20,
        description="Password must be between 12 to 20 characters",
    )


class RefreshRequest(BaseModel):
    refresh_token: str
