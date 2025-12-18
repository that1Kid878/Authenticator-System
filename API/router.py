from fastapi import APIRouter, FastAPI
from auth_services import HashPassword, ValidatePassword, ValidateUsername, Create_Access_Token
from schemas import LoginRequest, User
from database import db_dependency
from datetime import timedelta
import uvicorn

app = FastAPI()
User_Router = APIRouter(prefix="/users", tags=["Users"])
AuthN_Router = APIRouter(prefix="/auth", tags=["AuthN"])

@AuthN_Router.post("/login")
def login(Data:LoginRequest, DB:db_dependency):
    Hashed_Password = HashPassword(Data.password)
    UserData:User = ValidateUsername(Data.username, DB)
    ValidatePassword(UserData.hashed_password, Data.password)
    ExpiryDelta = timedelta(hours=2)

    Token = Create_Access_Token(
        Data.username,
        UserData.user_id,
        ExpiryDelta
        )
    return Token

app.include_router(AuthN_Router)

#Run server
if __name__ == "__main__":
    uvicorn.run("router:app", host="127.0.0.1", port=8000, reload=True)