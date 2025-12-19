from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import uuid
import secrets
from database import db_dependency
import bcrypt
from jose import jwt
from schemas import User, Refresh_Token
from fastapi import HTTPException, status
from Environmental_Variables import ACCESS_SECRET_KEY, REFRESH_TOKEN_PEPPER


Algorithm = "HS256"


def ValidateUsername(Username: str, DB: db_dependency):
    UserData = DB.query(User).filter(User.username == Username).first()
    if not UserData:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Username not found in database",
        )
    return UserData


def ValidatePassword(DB_Password_Hashed: str, Given_Password: str):
    DB_Password_Hashed_Encoded = DB_Password_Hashed.encode()
    Given_Password_Encoded = Given_Password.encode()

    if not bcrypt.checkpw(Given_Password_Encoded, DB_Password_Hashed_Encoded):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )


def Create_Access_Token(Username: str, User_ID: int, ExpiryDelta: timedelta):
    ExpiryDate = datetime.now(timezone.utc) + ExpiryDelta
    Token_Data = {"sub": Username, "id": User_ID, "exp": ExpiryDate}
    return jwt.encode(Token_Data, ACCESS_SECRET_KEY, Algorithm)


def Create_Refresh_Token(Token_id: uuid.UUID):
    REFRESH_SECRET_KEY = secrets.token_urlsafe(64)
    return f"{Token_id}.{REFRESH_SECRET_KEY}"


def Hash_Refresh_Token(Token: str):
    New_Token = hmac.new(
        REFRESH_TOKEN_PEPPER.encode(), Token.encode(), hashlib.sha256
    ).digest()
    return New_Token.hex()


def Rotate_Refresh_Token(
    DB_Token: Refresh_Token, Token: str, New_Token_Id: uuid.UUID, DB: db_dependency
):
    Hashed_Token = Hash_Refresh_Token(Token)
    DB_Token.token_hash = Hashed_Token
    DB_Token.token_id = New_Token_Id
    DB.commit()
    DB.refresh(DB_Token)


def Check_Refresh_Token(Token: str, DB: db_dependency):
    All_Valid_Refresh_Tokens: list[Refresh_Token] = (
        DB.query(Refresh_Token)
        .filter(Refresh_Token.expires_at > datetime.now(timezone.utc))
        .all()
    )
    Hashed_Token = Hash_Refresh_Token(Token)
    for token in All_Valid_Refresh_Tokens:
        Token_Valid = hmac.compare_digest(token.token_hash, Hashed_Token)
        if Token_Valid:
            return token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalid"
    )
