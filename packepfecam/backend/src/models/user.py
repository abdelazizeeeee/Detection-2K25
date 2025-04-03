from datetime import datetime
from pydantic import BaseModel
from typing import Optional
from beanie import Document


class Register(BaseModel):
    username: str
    email: str
    phone_number: str
    password: str
    department: str
    role : str


class Login(BaseModel):
    username: str
    email: str
    password: str


class UserResponse(BaseModel):
    username: str
    email: str
    phone_number: str
    department: str
    role : str
    message: Optional[str] = None


# This is the model that will be saved to the database


class User(Document):
    username: str
    email: str
    phone_number: str
    password: str
    created_at: Optional[datetime] = None
    verification_code: Optional[str] = None
    is_verified: bool = False
    department: str
    role : str
 
class UserUpdate(BaseModel):
    username: str
    email: str
    phone_number: str
