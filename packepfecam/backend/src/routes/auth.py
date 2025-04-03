from datetime import datetime, timedelta
from fastapi import APIRouter, Response, status, Depends, HTTPException, Path, Request
from ..models.user import User, Login, Register, UserResponse
from .. import utils
from .. import oauth2
from ..config.settings import settings

router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


# Register new User - to be removed if webapp is private
@router.post(
    "/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse
)
async def create_user(credentials: Register):
    if not utils.is_valid_email(credentials.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email"
        )
    if not utils.is_valid_phone_number(credentials.phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number"
        )

    user_exists = await User.find_one(User.username == credentials.username)
    email_exists = await User.find_one(User.email == credentials.email)
    phone_number_exists = await User.find_one(
        User.phone_number == credentials.phone_number
    )
    if user_exists or email_exists or phone_number_exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Account already exists"
        )

    new_user = User(
        username=credentials.username,
        email=credentials.email.lower(),
        phone_number=credentials.phone_number,
        password=utils.hash_password(credentials.password),
        created_at=datetime.utcnow(),
        department=credentials.department,
        role=credentials.role,
    )

    verification_code = utils.generate_verification_code()
    await utils.send_verification_email(new_user.email, verification_code)
    new_user.verification_code = verification_code
    await new_user.save()

    r_user = UserResponse(
        username=new_user.username,
        email=new_user.email,
        phone_number=new_user.phone_number,
        department=new_user.department,
        role=new_user.role,
        message="User registered. Check your email for verification.",
    )

    return r_user


async def send_verification_email(to_email: str, verification_code: str):
    await utils.send_verification_email(to_email, verification_code)


@router.post("/verify-email")
async def verify_email(email: str, verification_code: str):
    user = await User.find_one({"email": email, "verification_code": verification_code})

    if not user:
        raise HTTPException(status_code=404, detail="User not found or invalid code")

    user.is_verified = True
    await user.save()

    return {"message": "Email verified successfully"}


@router.post("/login")
async def login(credentials: Login, response: Response):
    user = await User.find_one(
        User.username == credentials.username,
        User.email == credentials.email,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found, Please check your username or email",
        )

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    if not utils.verify_password(credentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
        )

    access_token = oauth2.create_access_token(
        subject=str(user.id), 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN)
    )

    refresh_token = oauth2.create_refresh_token(
        subject=str(user.id), 
        expires_delta=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN)
    )

    response.set_cookie(
        "access_token",
        access_token,
        max_age=ACCESS_TOKEN_EXPIRES_IN * 60,
        expires=ACCESS_TOKEN_EXPIRES_IN * 60,
        path="/",
        domain=None,
        secure=False,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        max_age=REFRESH_TOKEN_EXPIRES_IN * 60,
        expires=REFRESH_TOKEN_EXPIRES_IN * 60,
        path="/",
        domain=None,
        secure=False,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        "logged_in",
        "True",
        max_age=ACCESS_TOKEN_EXPIRES_IN * 60,
        expires=ACCESS_TOKEN_EXPIRES_IN * 60,
        path="/",
        domain=None,
        secure=False,
        httponly=False,
        samesite="lax",
    )

    return {"status": "success", "access_token": access_token}


@router.get("/refresh")
async def refresh_token(response: Response, request: Request):
    try:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Please provide refresh token",
            )
        
        payload = oauth2.jwt.decode(
            refresh_token,
            oauth2.jwt_settings.jwt_public_key,
            algorithms=[oauth2.jwt_settings.jwt_algorithm]
        )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not refresh access token",
            )

        if datetime.fromtimestamp(payload.get("exp")) < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired",
            )

        user = await User.get(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The user belonging to this token no longer exists",
            )
            
        access_token = oauth2.create_access_token(
            subject=str(user.id),
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN),
        )
    except oauth2.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    except Exception as e:
        error = e.__class__.__name__
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    response.set_cookie(
        "access_token",
        access_token,
        max_age=ACCESS_TOKEN_EXPIRES_IN * 60,
        expires=ACCESS_TOKEN_EXPIRES_IN * 60,
        path="/",
        domain=None,
        secure=False,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        "logged_in",
        "True",
        max_age=ACCESS_TOKEN_EXPIRES_IN * 60,
        expires=ACCESS_TOKEN_EXPIRES_IN * 60,
        path="/",
        domain=None,
        secure=False,
        httponly=False,
        samesite="lax",
    )

    return {"access_token": access_token}


@router.get("/logout", status_code=status.HTTP_200_OK)
def logout(
    response: Response,
    user_id: str = Depends(oauth2.require_user),
):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("logged_in")

    return {"status": "success"}