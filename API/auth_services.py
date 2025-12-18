from database import db_dependency
import bcrypt
from jose import jwt
from schemas import User, Refresh_Token
from fastapi import HTTPException, status
from datetime import datetime, timedelta, timezone
from EnvVariables import SECRET_KEY

Algorithm = "HS256"

def HashPassword(password:str):
    Encoded_Password = password.encode()
    Salt = bcrypt.gensalt()
    Hashed_Password = bcrypt.hashpw(Encoded_Password, Salt)
    return Hashed_Password

def ValidateUsername(username:str, DB:db_dependency):
    Username = username
    UserData = DB.query(User).filter(User.username==Username).first()
    if not UserData:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Username not found in database"
        )
    return UserData

def ValidatePassword(DB_Password_Hashed:str, Given_Password:str):
    DB_Password_Hashed = DB_Password_Hashed.encode()
    Given_Password = Given_Password.encode()
    
    if not bcrypt.checkpw(Given_Password, DB_Password_Hashed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
def Create_Access_Token(Username:str, User_ID:int, ExpiryDelta:timedelta):
    ExpiryDate = datetime.now(timezone.utc) + ExpiryDelta
    Token_Data = {
        'sub': Username,
        'id': User_ID,
        'exp': ExpiryDate
    }
    return jwt.encode(Token_Data, SECRET_KEY, Algorithm)


    
    