from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel





class FileUpload(BaseModel):
    file: UploadFile
