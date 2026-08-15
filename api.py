import os
import json
import asyncio
from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess

from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException, Security, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
import subprocess
import time

app = FastAPI(title="Jailbreaker Dashboard API")

# Restricted CORS origins (allowed origins configured via env or localhost defaults)
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

API_KEY = os.getenv("JAILBREAKER_API_KEY", "")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(api_key: str = Depends(api_key_header)):
    if API_KEY and api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

# Simple in-memory rate limiting
request_timestamps = []

def rate_limiter():
    now = time.time()
    # Retain requests in the last 60 seconds
    global request_timestamps
    request_timestamps = [t for t in request_timestamps if now - t < 60]
    if len(request_timestamps) >= 30:  # Max 30 requests per minute
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 30 requests per minute.")
    request_timestamps.append(now)

class ScanRequest(BaseModel):
    objective: str
    target: str = "."
    target_url: str = ""
    model: str = "groq"

# Global state for connected clients to stream logs
active_connections = []

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def broadcast_log(message: str):
    for connection in active_connections:
        try:
            await connection.send_text(message)
        except Exception:
            pass

async def run_scan_task(req: ScanRequest):
    import sys
    cmd = [sys.executable, "run_objective.py", "--objective", req.objective, "--model", req.model]
    if req.target_url:
        cmd.extend(["--target-url", req.target_url])
    else:
        cmd.extend(["--target", req.target])
        
    await broadcast_log(f"Starting scan with command: {' '.join(cmd)}\n")
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    while True:
        line = await process.stdout.readline()
        if not line:
            break
        await broadcast_log(line.decode('utf-8'))
        
    await process.wait()
    await broadcast_log(f"\n--- Scan Complete (Exit Code: {process.returncode}) ---\n")

@app.post("/api/scan", dependencies=[Depends(verify_api_key), Depends(rate_limiter)])
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_scan_task, request)
    return {"status": "Scan started in background"}

@app.get("/api/results")
def get_results():
    sarif_path = "results.sarif"
    if not os.path.exists(sarif_path):
        return {"runs": []}
    try:
        with open(sarif_path, "r") as f:
            data = json.load(f)
        return data
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)
