#!/usr/bin/env python3
# auth_gateway.py
import os, json, uuid, requests
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()  # optional .env for MONGO_URI, REQUEST_TIMEOUT

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "mcp_auth")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))

# load backend mapping
with open("mcp_backends.json", "r") as f:
    BACKENDS = json.load(f)

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_col = db["users"]
sessions_col = db["sessions"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="MCP Gateway (Session Auth + Policy)")

# ---------- Models ----------
class LoginRequest(BaseModel):
    username: str
    password: str

# ---------- Helpers ----------
def create_session(username: str):
    session_id = str(uuid.uuid4())
    sessions_col.insert_one({
        "session_id": session_id,
        "username": username,
        "created_at": datetime.utcnow()
    })
    return session_id

def verify_session(session_id: str):
    session = sessions_col.find_one({"session_id": session_id})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session["username"]

# ---------- Endpoints ----------
@app.post("/register")
def register(req: LoginRequest):
    if users_col.find_one({"username": req.username}):
        raise HTTPException(status_code=400, detail="User already exists")
    hashed = pwd_context.hash(req.password)
    users_col.insert_one({"username": req.username, "password": hashed, "servers": []})
    return {"msg": "registered"}

@app.post("/login")
def login(req: LoginRequest):
    user = users_col.find_one({"username": req.username})
    if not user or not pwd_context.verify(req.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_id = create_session(req.username)
    return {"session_id": session_id, "allowed_servers": user.get("servers", [])}

@app.post("/assign_server/{username}")
def assign_server(username: str, server: str):
    if server not in BACKENDS:
        raise HTTPException(status_code=400, detail="Unknown server")
    users_col.update_one({"username": username}, {"$addToSet": {"servers": server}})
    return {"msg": f"assigned {server} to {username}"}

@app.get("/my_servers/{username}")
def my_servers(username: str):
    user = users_col.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"servers": user.get("servers", [])}

@app.post("/mcp")
async def mcp_handler(request: Request):
    """
    Expects JSON-RPC body. The client should call gateway with ?target=<servername>
    and include 'session_id' in the JSON-RPC body (client attaches automatically).
    """
    target = request.query_params.get("target")
    body = await request.json()

    # session must be in body
    session_id = body.get("session_id") or (body.get("params") or {}).get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Missing session_id in request body")

    username = verify_session(session_id)
    user = users_col.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # resolve target either from query or params
    if not target:
        target = (body.get("params") or {}).get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Missing target server (query param ?target=...)")

    if target not in user.get("servers", []):
        raise HTTPException(status_code=403, detail=f"Access denied to {target} for user {username}")

    backend_url = BACKENDS.get(target)
    if not backend_url:
        raise HTTPException(status_code=404, detail=f"No backend configured for {target}")

    # Forward request to backend MCP server
    try:
        # optionally add forwarded-user header
        headers = {"X-Forwarded-User": username}
        resp = requests.post(backend_url, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        # return backend response as-is (JSON-RPC)
        try:
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
        except Exception:
            return JSONResponse(content={"text": resp.text}, status_code=resp.status_code)
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Gateway forwarding failed: {str(e)}")
