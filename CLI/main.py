import api_requests
from collections.abc import Callable
import storage
import cmd
from termcolor import colored


def Valid_Refresh_Token():
    Refresh_Token = storage.Get_Refresh_Token()
    Response = api_requests.Use_Refresh_Token(Refresh_Token)
    if Response.get("Error"):
        return False
    storage.Add_Tokens(Response["access_token"], Response["refresh_token"])
    return True


def Handle_Unauthorized_Access_Tokens(Response: dict, func: Callable, args: str = ""):
    if Response.get("Error") == "Unauthorized":
        if Valid_Refresh_Token():
            func(args)
        else:
            print(colored("Please log in again", "red"))
    elif Response.get("Error"):
        print(colored(Response["Error"], "red"))


class TaskShell(cmd.Cmd):
    intro = "Welcome to the authentication system, key 'help' for list of commands"
    prompt = "<AuthN> "

    def do_login(self, args: str):
        """Log in to application"""
        Access_Token = storage.Get_Access_Token()
        if Access_Token is not None:
            print(colored("You are already logged in", "yellow"))
            return
        Username = input("Username: ")
        Password = input("Password: ")
        Response = api_requests.Login(Username, Password)
        if Response.get("Error"):
            print(colored(Response["Error"], "red"))
        else:
            Access_Token = Response.get("access_token")
            Refresh_Token = Response.get("refresh_token")
            storage.Add_Tokens(Access_Token, Refresh_Token)
            print(colored("Login successful!", "green"))

    def do_profile(self, args: str):
        """Get user data"""
        Access_Token = storage.Get_Access_Token()
        if Access_Token is None:
            print(colored("Please log in again", "red"))
            return
        Response = api_requests.GetUser(Access_Token)
        Handle_Unauthorized_Access_Tokens(Response, self.do_profile)

        if not Response.get("Error"):
            for key, value in Response.items():
                print(colored(f"{key.capitalize()}: {value}"))

    def do_change(self, args: str):
        """use 'change password' to change password"""
        if args != "password":
            return
        Old_Password = input("Current Password: ")
        New_Password = input("New Password: ")
        Access_Token = storage.Get_Access_Token()
        Response = api_requests.ChangePassword(Old_Password, New_Password, Access_Token)
        Handle_Unauthorized_Access_Tokens(Response, self.do_change, "password")

        if not Response.get("Error"):
            print(colored("Password change successful", "green"))

    def do_create(self, args: str):
        """use 'create user' to create a register user"""
        if args != "user":
            return
        Access_Token = storage.Get_Access_Token()
        if Access_Token is not None:
            print(
                colored(
                    "You are already logged in, logout before creating a new user",
                    "yellow",
                )
            )
        Username = input("Username: ")
        Password = input("Password: ")
        Response = api_requests.SignUp(Username, Password)

        if not Response.get("Error"):
            print(
                colored(
                    f"User {Response["ID"]} created successfully with the name {Response["Username"]}",
                    "green",
                )
            )

    def do_logout(self, args: str):
        """Log out of application"""
        Access_Token = storage.Get_Access_Token()
        Refresh_Token = storage.Get_Refresh_Token()
        Response = api_requests.Logout(Access_Token, Refresh_Token)
        Handle_Unauthorized_Access_Tokens(Response, self.do_logout, "")

        if not Response.get("Error"):
            storage.Delete_Tokens(True, True)
            print(colored("Logout successful", "green"))

    def do_delete(self, args: str):
        """Use 'delete user' to sign out of existing user"""
        if args != "user":
            return

        Access_Token = storage.Get_Access_Token()
        Response = api_requests.SignOut(Access_Token)
        Handle_Unauthorized_Access_Tokens(Response, self.do_delete, "user")

        if not Response.get("Error"):
            storage.Delete_Tokens(True, True)
            print(colored("Logout successful", "green"))


if __name__ == "__main__":
    TaskShell().cmdloop()
