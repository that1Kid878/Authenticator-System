import uuid
from datetime import timedelta
from fastapi import APIRouter, FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer
from auth_services import (
    ValidatePassword,
    ValidateUsername,
    Create_Access_Token,
    Validate_Access_Token,
    Create_New_DB_Refresh_Token,
    Create_Refresh_Token,
    Check_Refresh_Token,
    Rotate_Refresh_Token,
)
from schemas import LoginRequest, User, RefreshRequest, LogoutRequest
from database import db_dependency
import uvicorn

OAuth2_Scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
app = FastAPI()
User_Router = APIRouter(prefix="/users", tags=["Users"])
AuthN_Router = APIRouter(prefix="/auth", tags=["AuthN"])


@AuthN_Router.post("/login")
async def login(Data: LoginRequest, DB: db_dependency):
    UserData: User = ValidateUsername(Data.username, DB)
    ValidatePassword(UserData.hashed_password, Data.password)
    Access_ExpiryDelta = timedelta(hours=2)
    Refresh_ExpiryDelta = timedelta(days=30)

    Access_Token = Create_Access_Token(
        Data.username, UserData.user_id, Access_ExpiryDelta
    )
    Refresh_Token = Create_New_DB_Refresh_Token(
        UserData.user_id, Refresh_ExpiryDelta, DB
    )
    output = {"access_token": Access_Token, "refresh_token": Refresh_Token}
    return output


@AuthN_Router.post("/logout")
async def logout(
    Data: LogoutRequest, DB: db_dependency, Token: str = Depends(OAuth2_Scheme)
):
    Validate_Access_Token(Token)
    DB_Refresh_Token = Check_Refresh_Token(Data.refresh_token, DB)
    DB_Refresh_Token.revoked = True
    DB.commit()
    DB.refresh(DB_Refresh_Token)


@AuthN_Router.post("/refresh")
async def RefreshToken(Data: RefreshRequest, DB: db_dependency):
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
