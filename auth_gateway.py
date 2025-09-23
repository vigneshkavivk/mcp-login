#!/usr/bin/env python3
# auth_gateway.py
import os
import json
import uuid
import requests
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "mcp_auth")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))

# Load backend mapping (maps backend name -> real server url)
with open("mcp_backends.json", "r") as f:
    BACKENDS = json.load(f)

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_col = db["users"]
sessions_col = db["sessions"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="MCP Gateway (Session Auth + Policy)")

class LoginRequest(BaseModel):
    username: str
    password: str

# Session helpers (simple DB-backed sessions)
def create_session(username: str):
    session_id = str(uuid.uuid4())
    sessions_col.insert_one({
        "session_id": session_id,
        "username": username,
        "created_at": datetime.utcnow()
    })
    return session_id

def get_or_create_session(username: str):
    existing = sessions_col.find_one({"username": username})
    if existing:
        return existing["session_id"]
    return create_session(username)

def verify_session(session_id: str):
    session = sessions_col.find_one({"session_id": session_id})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session["username"]

# Register (optional)
@app.post("/register")
def register(req: LoginRequest):
    if users_col.find_one({"username": req.username}):
        raise HTTPException(status_code=400, detail="User already exists")
    hashed = pwd_context.hash(req.password)
    users_col.insert_one({"username": req.username, "password": hashed, "access": []})
    return {"msg": "registered"}

# Login
@app.post("/login")
def login(req: LoginRequest):
    user = users_col.find_one({"username": req.username})
    if not user or not pwd_context.verify(req.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_id = get_or_create_session(req.username)
    # Return username + access to client so client can render UI
    return {
        "message": "Login successful",
        "session_id": session_id,
        "username": req.username,
        "access": user.get("access", [])
    }

# Logout
@app.post("/logout")
def logout(req: LoginRequest):
    user = users_col.find_one({"username": req.username})
    if not user or not pwd_context.verify(req.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    sessions_col.delete_one({"username": req.username})
    return {"msg": f"User {req.username} logged out, session cleared"}

# Assign access to a user (admin helper)
@app.post("/assign_server/{username}")
def assign_server(username: str, server: str):
    if server not in BACKENDS:
        raise HTTPException(status_code=400, detail="Unknown server")
    users_col.update_one({"username": username}, {"$addToSet": {"access": server}})
    return {"msg": f"assigned {server} to {username}"}

# Get user access
@app.get("/my_servers/{username}")
def my_servers(username: str):
    user = users_col.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"access": user.get("access", [])}

# Main MCP forward endpoint (JSON-RPC style expected)
@app.post("/mcp")
async def mcp_handler(request: Request):
    """
    Client must call: POST /mcp?target=<backend>
    Body must include session_id (top-level) OR in params.session_id.
    The gateway verifies session -> checks user.access -> forwards to backend.
    """
    target = request.query_params.get("target")
    body = await request.json()

    session_id = body.get("session_id") or (body.get("params") or {}).get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Missing session_id in request body")

    username = verify_session(session_id)
    user = users_col.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not target:
        target = (body.get("params") or {}).get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Missing target server (use ?target=<name> or params.target)")

    if target not in user.get("access", []):
        raise HTTPException(status_code=403, detail=f"Access denied to {target} for user {username}")

    backend_url = BACKENDS.get(target)
    if not backend_url:
        raise HTTPException(status_code=404, detail=f"No backend configured for {target}")

    # Forward to backend, attach X-Forwarded-User
    try:
        headers = {"X-Forwarded-User": username, "Content-Type": "application/json"}
        resp = requests.post(backend_url, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        try:
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
        except Exception:
            return JSONResponse(content={"text": resp.text}, status_code=resp.status_code)
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Gateway forwarding failed: {str(e)}")

