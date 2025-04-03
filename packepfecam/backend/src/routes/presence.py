import json
import os
import cv2
from fastapi import APIRouter, File, UploadFile,status
from ultralytics import YOLO
import aiofiles
from ..models.response import VideoResponse  
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from ..config.settings import settings
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader
from ..models.api_key import ApiKey


router = APIRouter()
api_key_header = APIKeyHeader(name="X-API-Key")





async def get_api_key(api_key_header: str = Security(api_key_header)) -> str:
    key = await ApiKey.find_one(ApiKey.value == api_key_header)
    if key:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )

client = AsyncIOMotorClient(settings.DATABASE_URL)
db = client.db_name
collection = db["User"]
 
# Load the YOLO model during startup
model = YOLO("/app/src/routes/YOLO/best.pt") 
 
output_json_file = "/app/FILES/name_durations.json"
names_json_file = "/app/FILES/results.json"
video_dir = "/app/uploads/"
 
 
async def save_to_database(name_durations: dict, video_name:str, api_key: str):
    try:
        names_response = VideoResponse(names=name_durations, date=(datetime.now() + timedelta(hours=1)), video_name=video_name, api_key=api_key)
        await VideoResponse.insert_one(names_response)
    except Exception as e:
        raise e
 
 
 
async def process_video(video_file: UploadFile, api_key):
    print("Processing video...")
    try:
        with open(names_json_file, "r") as f:
            names_data = json.load(f)
 
        name_durations = {entry["name"]: 0 for entry in names_data}
 
        video_path = os.path.join(video_dir, video_file.filename)
        async with aiofiles.open(video_path, "wb") as buffer:
            while True:
                chunk = await video_file.read(1024)
                if not chunk:
                    break
                await buffer.write(chunk)
 
        cap = cv2.VideoCapture(video_path)
 
        if not cap.isOpened():
            raise Exception("Failed to open video file")
 
        fps = cap.get(cv2.CAP_PROP_FPS)  
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))  
 
        for _ in range(total_frames):
            ret, frame = cap.read()
            if not ret:
                break  
 
            results = model(frame)
 
            for r in results:
                for name_data in names_data:
                    if name_data["class"] in r.boxes.cls:
                        name = name_data["name"]
                        name_durations[name] += 1
 
        # Transform durations to seconds and add "sec" to each value
        for name in name_durations:
            name_durations[name] /= fps
            name_durations[name] = round(name_durations[name])
            name_durations[name] = str(name_durations[name]) + "sec"
        print(name_durations)
        response_data = []
        for name, duration in name_durations.items():
            user_data = await collection.find_one({"username": name})   
            email = user_data.get("email") if user_data else "N/A"
            phone_number = user_data.get("phone_number") if user_data else "N/A"
            department = user_data.get("department") if user_data else "N/A"
            role = user_data.get("role") if user_data else "N/A"
            print(f"Name: {name}, Attendance: {duration}, Email: {email}, Phone: {phone_number}", "\n\n\n")
            name_durations[name] = {
                "duration": duration,
                "email": email,
                "phone_number": phone_number,
                "department": department,
                "role": role
            }
            response_data.append({
                "name": name,
                "duration": duration,
                "email": email,
                "phone_number": phone_number,
                "department": department,
                "role": role,
                "attendance": "Present" if duration != "0sec" else "Absent"
            })
 
 
        video_name = f"app/uploads/{video_file.filename}"
        await save_to_database(name_durations, video_name,api_key)
       
        with open(output_json_file, "w") as json_file:
            json.dump(name_durations, json_file)
 
        # Close the video file
        cap.release()
 
        # Delete the video file
        # os.remove(video_path)
 
        return response_data
 
    except Exception as e:
        raise e
 

@router.post("/process_video")
async def process_video_endpoint(video_file: UploadFile = File(...),api_key: str = Security(get_api_key)):
    try:
        response = await process_video(video_file,str(api_key))
    
        success_message = "Video processing completed successfully!"
        print(success_message)
        return {"results":response,"video_file": f"app/uploads/{video_file.filename}"}
    except Exception as e:
        return {"error": str(e)}