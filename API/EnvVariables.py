from dotenv import load_dotenv
import os

load_dotenv()
Database_URL = os.getenv("Database_URL")
ACCESS_SECRET_KEY=os.getenv("ACCESS_SECRET_KEY")
REFRESH_TOKEN_PEPPER = os.getenv("REFRESH_TOKEN_PEPPER")