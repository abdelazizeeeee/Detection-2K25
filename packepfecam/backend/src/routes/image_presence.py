import json
import os
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
import cv2
from ultralytics import YOLO
import numpy as np
from PIL import Image
from ..models.response import ProcessedImageResponse, UserData
from ..utils import save_json_file

router = APIRouter()

# Initialize YOLO model
BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = Path(__file__).resolve().parent / "YOLO" / "best.pt"
FILES_DIR = BASE_DIR / "FILES"

FILES_DIR.mkdir(parents=True, exist_ok=True)

output_json_file = str(FILES_DIR / "name_durations.json")
output_image_file = str(FILES_DIR / "results.jpg")
names_json_file = str(FILES_DIR / "results.json")

if not os.path.exists(names_json_file):
    with open(names_json_file, "w") as f:
        json.dump([], f)

model = YOLO(str(MODEL_PATH))


async def get_user_data(name: str):
    return None

async def process_image_file(file: UploadFile):
    content = await file.read()
    nparr = np.frombuffer(content, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    return img


async def save_to_database(name_durations: list):
    return None


async def process_results(results, names_data):
    name_durations = {name_data["name"]: "Absent" for name_data in names_data}
    for r in results:
        for name_data in names_data:
            if name_data["class"] in r.boxes.cls:
                name = name_data["name"]
                name_durations[name] = "Present"
    return name_durations

async def prepare_response(name_durations):
    response_data = []
    for name, duration in name_durations.items():
        user_data = await get_user_data(name)
        email = user_data.get("email") if user_data else "N/A"
        phone_number = user_data.get("phone_number") if user_data else "N/A"
        department = user_data.get("department") if user_data else "N/A"
        role = user_data.get("role") if user_data else "N/A"
        print(f"Name: {name}, Attendance: {duration}, Email: {email}, Phone: {phone_number}", "\n\n\n")
        response_data.append(UserData(name=name ,attendance=duration, email=email, phone_number=phone_number, department=department, role=role))
    await save_to_database(response_data)
    return response_data


@router.post("/process_image", response_model=ProcessedImageResponse)
async def process_image(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    try:
        with open(names_json_file, "r") as f:
            names_data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Results file not found.")
    
    img = await process_image_file(file)
    results = model(img)
    name_durations = await process_results(results, names_data)
    await save_json_file(name_durations, output_json_file)

    for r in results:
        im_array = r.plot()
        im = Image.fromarray(im_array[..., ::-1])
        im.save(output_image_file)

    processed_image_response = await prepare_response(name_durations)



    json_file_path = str(output_json_file)
    image_file_path = str(output_image_file)

    return ProcessedImageResponse(
        message="Processing completed. Check JSON file for results.",
        results=processed_image_response,
        json_file=json_file_path,
        image_with_boxes=image_file_path  
    )

@router.get("/get-json_file")
async def download_json_file():
    try:
        return FileResponse(output_json_file)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="JSON file not found.")

@router.get("/get-image_file")
async def download_image_file():
    try:
        return FileResponse(output_image_file)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Image file not found.")
