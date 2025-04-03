import base64
from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer # type: ignore
from jose import jwt, JWTError
from pydantic import BaseModel

from .models.user import User
from .config.settings import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)

class Settings(BaseModel):
    jwt_algorithm: str = settings.JWT_ALGORITHM
    jwt_public_key: str = settings.JWT_PUBLIC_KEY
    jwt_private_key: str = settings.JWT_PRIVATE_KEY
    access_token_expire_minutes: int = 30
    refresh_token_expire_minutes: int = 60 * 24 * 7  # 7 days


jwt_settings = Settings()


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=jwt_settings.access_token_expire_minutes)
    
    to_encode = {"exp": expire, "sub": subject}
    encoded_jwt = jwt.encode(
        to_encode, 
        jwt_settings.jwt_private_key, 
        algorithm=jwt_settings.jwt_algorithm
    )
    return encoded_jwt


def create_refresh_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=jwt_settings.refresh_token_expire_minutes)
    
    to_encode = {"exp": expire, "sub": subject}
    encoded_jwt = jwt.encode(
        to_encode, 
        jwt_settings.jwt_private_key, 
        algorithm=jwt_settings.jwt_algorithm
    )
    return encoded_jwt


async def get_token_from_request(request: Request) -> Optional[str]:
    # Try to get token from cookies
    token = request.cookies.get("access_token")
    if token:
        return token
    
    # Try to get token from headers
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "")
    
    return None


async def require_user(request: Request = None, token: str = Depends(oauth2_scheme)):
    if request and not token:
        token = await get_token_from_request(request)
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not logged in",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        payload = jwt.decode(
            token,
            jwt_settings.jwt_public_key,
            algorithms=[jwt_settings.jwt_algorithm]
        )
        token_data = TokenPayload(**payload)
        
        if datetime.fromtimestamp(token_data.exp) < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_id = token_data.sub
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = await User.get(str(user_id))
        if not user:
            raise UserNotFound("User no longer exists")
        
        # if not user["verified"]:
        #     raise NotVerified('You are not verified')

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except UserNotFound:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists"
        )
    except NotVerified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please verify your account"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user_id