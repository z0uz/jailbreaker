import os
import json
import asyncio
from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess

app = FastAPI(title="Jailbreaker Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.post("/api/scan")
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
