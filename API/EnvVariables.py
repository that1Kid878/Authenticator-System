from dotenv import load_dotenv
import os

load_dotenv()
Database_URL = os.getenv("Database_URL")
SECRET_KEY=os.getenv("SECRET_KEY")