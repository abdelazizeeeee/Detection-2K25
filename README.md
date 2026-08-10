# Video Presence API

FastAPI service that runs YOLO over uploaded video and images to detect
presence. Containerised and deployed on Render.

## What it does

- Accepts video and image uploads
- Runs YOLO detection over them
- Serves processed uploads as static files

## Stack

FastAPI · YOLO · Docker · Render

## Running it

```bash
cd packepfecam
cp .env.Example .env
docker compose up --build
```

Interactive API docs are served at `/docs`, health check at `/api/healthchecker`.
