import json
import os
import cv2
from fastapi import APIRouter, File, UploadFile
from ultralytics import YOLO
import aiofiles

router = APIRouter()

# Load the YOLO model during startup
model = YOLO("/app/src/routes/YOLO/best.pt") 

output_json_file = "/app/FILES/name_durations.json"
names_json_file = "/app/FILES/results.json"
video_dir = "/app/uploads/"

async def process_video(video_file: UploadFile):
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
            email = "N/A"
            phone_number = "N/A"
            department = "N/A"
            role = "N/A"
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
async def process_video_endpoint(video_file: UploadFile = File(...)):
    try:
        response = await process_video(video_file)

        success_message = "Video processing completed successfully!"
        print(success_message)
        return {"results":response,"video_file": f"app/uploads/{video_file.filename}"}
    except Exception as e:
        return {"error": str(e)}
