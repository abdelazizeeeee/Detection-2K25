from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv

load_dotenv()



class Settings(BaseSettings):
    JWT_PUBLIC_KEY: str = os.getenv("JWT_PUBLIC_KEY", "")
    JWT_PRIVATE_KEY: str = os.getenv("JWT_PRIVATE_KEY", "")
    REFRESH_TOKEN_EXPIRES_IN: int = int(os.getenv("REFRESH_TOKEN_EXPIRES_IN", "60"))
    ACCESS_TOKEN_EXPIRES_IN: int = int(os.getenv("ACCESS_TOKEN_EXPIRES_IN", "15"))
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "RS256")
    CLIENT_ORIGIN: str = os.getenv("CLIENT_ORIGIN", "*")


settings = Settings()
