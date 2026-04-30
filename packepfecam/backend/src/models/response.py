from pydantic import BaseModel
from typing import List



class UserData(BaseModel):
    name: str
    attendance: str
    email: str
    phone_number: str
    department: str = None
    role: str = None


class ProcessedImageResponse(BaseModel):
    message: str
    results: List[UserData]
    json_file: str
    image_with_boxes: str


class FileDownload(BaseModel):
    download_link: str
    description: str



