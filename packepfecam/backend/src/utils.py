import base64
from urllib.parse import parse_qs
from dotenv import load_dotenv
from passlib.context import CryptContext
import re
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from .models.response import ImageResponse
from fastapi import HTTPException
import json
import os
def is_valid_email(email: str) -> bool:
    pat = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if re.match(pat, email):
        return True
    return False


def is_valid_phone_number(phone_number: str) -> bool:
    pat = "^[0-9]{8}$"

    if re.match(pat, phone_number):
        return True
    return False


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)


def generate_verification_code():
    return secrets.token_urlsafe(6)


def get_smtp_connection():
    # smtp_server = "smtp.sendgrid.net"
    # smtp_port = 587
    # smtp_username = "apikey"
    # sendgrid_api_key = os.getenv("SENDGRID_API_KEY")
    # smtp_password = sendgrid_api_key
    # smtp_from_email = "oussema.benhassena@horizon-tech.tn"
    # return smtp_server, smtp_port, smtp_username, smtp_password, smtp_from_email
    pass


async def send_verification_email(to_email: str, verification_code: str):
    (
        smtp_server,
        smtp_port,
        smtp_username,
        smtp_password,
        smtp_from_email,
    ) = get_smtp_connection()

    # Create the MIME message
    subject = "Email Verification Code"
    body = f"Your verification code is: {verification_code}"

    message = MIMEMultipart()
    message["From"] = smtp_from_email
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    # Connect to the SMTP server and send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_from_email, to_email, message.as_string())






async def save_json_file(data: dict, file_path: str):
    try:
        with open(file_path, "w") as json_file:
            json.dump(data, json_file)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving JSON file: {str(e)}")