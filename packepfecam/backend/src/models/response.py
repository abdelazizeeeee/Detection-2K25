from beanie import Document
from datetime import datetime
from pydantic import BaseModel
from typing import Any, Dict, Union, List


class VideoResponse(Document): 
    names: dict
    date: datetime
    video_name: str
    api_key: str



class UserData(BaseModel):
    name: str
    attendance: str
    email: str
    phone_number: str
    department: str = None
    role: str = None


class ImageResponse(Document): 
    names: List[UserData]
    date: datetime


class ProcessedImageResponse(BaseModel):
    message: str
    results: List[UserData]
    json_file: str
    image_with_boxes: str


class FileDownload(BaseModel):
    download_link: str
    description: str



