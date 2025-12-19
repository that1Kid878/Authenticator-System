import uuid
from datetime import timedelta
from fastapi import APIRouter, FastAPI
from auth_services import ValidatePassword, ValidateUsername, Create_Access_Token
from auth_services import (
    Create_Refresh_Token,
    Check_Refresh_Token,
    Rotate_Refresh_Token,
)
from schemas import LoginRequest, User, RefreshRequest
from database import db_dependency
import uvicorn

app = FastAPI()
User_Router = APIRouter(prefix="/users", tags=["Users"])
AuthN_Router = APIRouter(prefix="/auth", tags=["AuthN"])


@AuthN_Router.post("/login")
def login(Data: LoginRequest, DB: db_dependency):
    UserData: User = ValidateUsername(Data.username, DB)
    ValidatePassword(UserData.hashed_password, Data.password)
    ExpiryDelta = timedelta(hours=2)

    Token = Create_Access_Token(Data.username, UserData.user_id, ExpiryDelta)
    return Token


@AuthN_Router.post("/refresh")
def RefreshToken(Data: RefreshRequest, DB: db_dependency):
    Existing_Token = Check_Refresh_Token(Data.refresh_token, DB)
    UserData = DB.query(User).filter(User.user_id == Existing_Token.user_id).first()
    Access_Token = Create_Access_Token(
        UserData.username, UserData.user_id, timedelta(hours=2)
    )
    New_Token_Id = uuid.uuid4()
    Refresh_Token = Create_Refresh_Token(New_Token_Id)
    Rotate_Refresh_Token(Existing_Token, Refresh_Token, New_Token_Id, DB)

    output = {"access_token": Access_Token, "refresh_token": Refresh_Token}

    return output


app.include_router(AuthN_Router)

# Run server
if __name__ == "__main__":
    uvicorn.run("router:app", host="127.0.0.1", port=8000, reload=True)
