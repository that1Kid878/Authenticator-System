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
    Create_User,
    Validate_User_ID,
    Refine_User_Data,
    Hash_String,
)
from schemas import (
    Username_Password_Schema,
    User,
    Refresh_Token_Schema,
    Change_Password_Schema,
)
from database import db_dependency
import uvicorn

OAuth2_Scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
app = FastAPI()
User_Router = APIRouter(prefix="/users", tags=["Users"])
AuthN_Router = APIRouter(prefix="/auth", tags=["AuthN"])


@AuthN_Router.post("/login")
async def login(Data: Username_Password_Schema, DB: db_dependency):
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
    Data: Refresh_Token_Schema, DB: db_dependency, Token: str = Depends(OAuth2_Scheme)
):
    Validate_Access_Token(Token)
    DB_Refresh_Token = Check_Refresh_Token(Data.refresh_token, DB)
    DB_Refresh_Token.revoked = True
    DB.commit()
    DB.refresh(DB_Refresh_Token)


@AuthN_Router.post("/refresh")
async def RefreshToken(Data: Refresh_Token_Schema, DB: db_dependency):
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


@User_Router.post("/signup", status_code=201)
async def SignUp(Data: Username_Password_Schema, DB: db_dependency):
    Username = Data.username
    Password = Data.password
    UserData = Create_User(Username, Password, DB)
    return Refine_User_Data(UserData)


@User_Router.get("/me")
async def GetUser(DB: db_dependency, Token: str = Depends(OAuth2_Scheme)):
    Payload = Validate_Access_Token(Token)
    User_ID = Payload["id"]
    UserData = Validate_User_ID(User_ID, DB)
    return Refine_User_Data(UserData)


@User_Router.put("/password")
async def Change_Password(
    Data: Change_Password_Schema, DB: db_dependency, Token: str = Depends(OAuth2_Scheme)
):
    Payload = Validate_Access_Token(Token)
    UserData = Validate_User_ID(Payload["id"], DB)
    ValidatePassword(UserData.hashed_password, Data.old_password)

    Hashed_New_Password = Hash_String(Data.new_password)
    DB_User = DB.query(User).filter(User.user_id == Payload["id"]).first()
    DB_User.hashed_password = Hashed_New_Password
    DB.commit()
    DB.refresh(DB_User)


@User_Router.delete("/signout")
async def SignOut(DB: db_dependency, Token: str = Depends(OAuth2_Scheme)):
    Payload = Validate_Access_Token(Token)
    User_ID = Payload["id"]
    UserData = Validate_User_ID(User_ID, DB)
    DB.delete(UserData)
    DB.commit()

    return {"detail": "Deletion successful"}


app.include_router(AuthN_Router)
app.include_router(User_Router)

# Run server
if __name__ == "__main__":
    uvicorn.run("router:app", host="127.0.0.1", port=8000, reload=True)
