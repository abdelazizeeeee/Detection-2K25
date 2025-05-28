from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.settings import settings
from src.config.database import startDB
from src.routes import auth, presence, image_presence, admin
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Video Presence API", description="API for Video Presence", version="2.0.0")
app.mount("/app/uploads", StaticFiles(directory="/app/uploads"), name="uploads")

origins = [
    settings.CLIENT_ORIGIN,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins="*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def start_dependencies():
    await startDB()
    # await startMinio()



app.include_router(auth.router, tags=["Auth"], prefix="/api/auth")
app.include_router(presence.router, tags=["Video Process"], prefix="/api/presence")
app.include_router(image_presence.router, tags=["ImagePresence"], prefix="/api/image-presence")
app.include_router(admin.router, tags=["Admin"], prefix="/api/admin")

@app.get("/api/healthchecker")
def root():
    return {"message": "Welcome to FastAPI with MongoDB"}
