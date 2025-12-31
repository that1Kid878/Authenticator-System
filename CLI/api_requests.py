import requests
from json import dumps as jsonify

link = "http://127.0.0.1:8000"


def Proccessed_Request_Results(
    Response: requests.Response, default_status_code: int = 200
):
    Returnable_Response_Variable: dict = Response.json()
    if Response.status_code != default_status_code:
        return {"Error": Returnable_Response_Variable.get("details", Response.reason)}
    return Returnable_Response_Variable


def SignUp(Username: str, Password: str):
    data = {"username": Username, "password": Password}
    result = requests.post(url=f"{link}/users/signup", data=jsonify(data, indent=4))
    return Proccessed_Request_Results(result, 201)


def SignOut(Access_Token: str):
    headers = {"Authorization": f"Bearer {Access_Token}"}
    result = requests.delete(url=f"{link}/users/signout", headers=headers)
    return Proccessed_Request_Results(result)


def ChangePassword(Old_Password: str, New_Password: str, Access_Token: str):
    headers = {"Authorization": f"Bearer {Access_Token}"}
    data = {"old_password": Old_Password, "new_password": New_Password}
    result = requests.put(
        url=f"{link}/users/password", headers=headers, data=jsonify(data, indent=4)
    )
    return Proccessed_Request_Results(result)


def GetUser(Access_Token: str):
    headers = {"Authorization": f"Bearer {Access_Token}"}
    result = requests.get(url=f"{link}/users/me", headers=headers)
    return Proccessed_Request_Results(result)


def Login(Username: str, Password: str):
    data = {"username": Username, "password": Password}
    result = requests.post(url=f"{link}/auth/login", data=jsonify(data, indent=4))
    return Proccessed_Request_Results(result)


def Logout(Access_Token: str, Refresh_Token: str):
    headers = {"Authorization": f"Bearer {Access_Token}"}
    data = {"refresh_token": Refresh_Token}
    result = requests.post(
        url=f"{link}/auth/logout", data=jsonify(data, indent=4), headers=headers
    )
    return Proccessed_Request_Results(result)


def Use_Refresh_Token(Refresh_Token: str):
    data = {"refresh_token": Refresh_Token}
    result = requests.post(url=f"{link}/auth/refresh", data=jsonify(data, indent=4))
    return Proccessed_Request_Results(result)
