import keyring


def Add_Tokens(Access_Token: str | None = None, Refresh_Token: str | None = None):
    if Access_Token:
        keyring.set_password("AuthN-CLI", "access_token", Access_Token)
    if Refresh_Token:
        keyring.set_password("AuthN-CLI", "refresh_token", Refresh_Token)


def Get_Access_Token():
    return keyring.get_password("AuthN-CLI", "access_token")


def Get_Refresh_Token():
    return keyring.get_password("AuthN-CLI", "refresh_token")


def Delete_Tokens(Access_Token: str | None = None, Refresh_Token: str | None = None):
    if Access_Token:
        keyring.delete_password("AuthN-CLI", "access_token")
    if Refresh_Token:
        keyring.delete_password("AuthN-CLI", "refresh_token")
