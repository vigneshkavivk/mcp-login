#!/usr/bin/env python3
"""
MasaBot MCP Server (FastAPI + ArgoCD)
--------------------------------------
- Supports JSON-RPC MCP tools (for MasaBot client)
- Also provides REST-style /mcp/* endpoints for direct usage
- Includes simple /list-apps and /health endpoints
"""

import os
import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ---- Config ----
ARGOCD_SERVER = os.getenv("ARGOCD_SERVER", "http://localhost:8080")
ARGOCD_TOKEN = os.getenv("ARGOCD_TOKEN", "")

HEADERS = {
    "Authorization": f"Bearer {ARGOCD_TOKEN}",
    "Content-Type": "application/json"
}

# ---- FastAPI App ----
app = FastAPI()

# ---- ArgoCD Helpers ----
def argocd_get(path: str, params: dict | None = None):
    url = f"{ARGOCD_SERVER}/api/v1{path}"
    try:
        resp = requests.get(url, headers=HEADERS, params=params, verify=False)
        if resp.status_code != 200:
            return {"error": resp.text, "status": resp.status_code}
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def argocd_post(path: str, body: dict | None = None):
    url = f"{ARGOCD_SERVER}/api/v1{path}"
    try:
        resp = requests.post(url, headers=HEADERS, json=body, verify=False)
        if resp.status_code not in (200, 201):
            return {"error": resp.text, "status": resp.status_code}
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def argocd_delete(path: str):
    url = f"{ARGOCD_SERVER}/api/v1{path}"
    try:
        resp = requests.delete(url, headers=HEADERS, verify=False)
        if resp.status_code not in (200, 202):
            return {"error": resp.text, "status": resp.status_code}
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


# =======================================================
# 🔹 NEW ENDPOINT 1: Login (Dynamic Token)
# =======================================================
@app.post("/login")
async def login(req: Request):
    data = await req.json()
    username = data.get("username")
    password = data.get("password")

    try:
        resp = requests.post(
            f"{ARGOCD_SERVER}/api/v1/session",
            json={"username": username, "password": password},
            verify=False
        )
        if resp.status_code != 200:
            return {"error": resp.text, "status": resp.status_code}

        token = resp.json().get("token")
        return {"token": token}
    except Exception as e:
        return {"error": str(e)}


# =======================================================
# 🔹 NEW ENDPOINT 2: Application Status (Health + Sync)
# =======================================================
@app.get("/mcp/status/{app_name}")
def app_status(app_name: str):
    data = argocd_get(f"/applications/{app_name}")
    if "error" in data:
        return data

    return {
        "application": app_name,
        "sync": data["status"].get("sync", {}).get("status", "Unknown"),
        "health": data["status"].get("health", {}).get("status", "Unknown"),
        "repo": data["spec"]["source"].get("repoURL"),
        "revision": data["status"].get("sync", {}).get("revision", "HEAD")
    }


# =======================================================
# 🔹 NEW ENDPOINT 3: Webhook (Forward Alerts to Discord/Slack)
# =======================================================
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")  # set in .env

@app.post("/webhook")
async def webhook(req: Request):
    data = await req.json()
    if not WEBHOOK_URL:
        return {"error": "WEBHOOK_URL not configured"}

    try:
        resp = requests.post(WEBHOOK_URL, json=data, timeout=5)
        if resp.status_code not in (200, 204):
            return {"error": resp.text, "status": resp.status_code}
        return {"status": "ok", "forwarded": True}
    except Exception as e:
        return {"error": str(e)}

# ---- MCP Tool Registry (for JSON-RPC) ----
MCP_TOOLS = {
    "list_applications": {
        "description": "List all ArgoCD applications",
        "handler": lambda args: argocd_get("/applications")
    },
    "get_application": {
        "description": "Get details of a specific ArgoCD application",
        "handler": lambda args: argocd_get(f"/applications/{args['application_name']}")
    },
    "sync_application": {
        "description": "Trigger sync for an ArgoCD application",
        "handler": lambda args: argocd_post(f"/applications/{args['application_name']}/sync")
    },
    "create_application": {
        "description": "Create an ArgoCD application",
        "handler": lambda args: argocd_post("/applications", {
            "metadata": {"name": args["name"]},
            "spec": {
                "project": "default",
                "source": {
                    "repoURL": args["repo_url"],
                    "path": args["path"],
                    "targetRevision": args.get("revision", "HEAD"),
                },
                "destination": {
                    "server": "https://kubernetes.default.svc",
                    "namespace": args.get("dest_ns", "default"),
                },
            },
            **({"syncPolicy": {"automated": {}}} if args.get("sync_policy") == "automated" else {})
        })
    },

    # ---- Extra tools ----
    "delete_application": {
        "description": "Delete an ArgoCD application",
        "handler": lambda args: requests.delete(
            f"{ARGOCD_SERVER}/api/v1/applications/{args['application_name']}",
            headers=HEADERS,
            verify=False
        ).json()
    },
    "get_application_history": {
        "description": "Get sync and revision history of an ArgoCD application",
        "handler": lambda args: argocd_get(f"/applications/{args['application_name']}/revisions")
    },
    "rollback_application": {
        "description": "Rollback an ArgoCD application to a specific revision",
        "handler": lambda args: argocd_post(
            f"/applications/{args['application_name']}/rollback",
            {"revision": args["revision"]}
        )
    },
    "refresh_application": {
        "description": "Refresh an ArgoCD application state from Git and cluster",
        "handler": lambda args: argocd_post(
            f"/applications/{args['application_name']}/refresh"
        )
    },
    "get_application_logs": {
        "description": "Fetch logs/events for an ArgoCD application",
        "handler": lambda args: argocd_get(f"/applications/{args['application_name']}/events")
    },
    "pause_application": {
        "description": "Pause auto-sync for an ArgoCD application",
        "handler": lambda args: argocd_post(
            f"/applications/{args['application_name']}/pause"
        )
    },
    "resume_application": {
        "description": "Resume auto-sync for an ArgoCD application",
        "handler": lambda args: argocd_post(
            f"/applications/{args['application_name']}/resume"
        )
    },
    "compare_application": {
        "description": "Compare live vs desired state of an ArgoCD application",
        "handler": lambda args: argocd_get(f"/applications/{args['application_name']}/diff")
    },
    "health_check": {
        "description": "Check health status of an ArgoCD application",
        "handler": lambda args: argocd_get(f"/applications/{args['application_name']}")
    },
    "list_projects": {
        "description": "List all ArgoCD projects",
        "handler": lambda args: argocd_get("/projects")
    },
    "get_project": {
        "description": "Get details of an ArgoCD project",
        "handler": lambda args: argocd_get(f"/projects/{args['project_name']}")
    },
    "create_project": {
        "description": "Create a new ArgoCD project",
        "handler": lambda args: argocd_post("/projects", {
            "metadata": {"name": args["project_name"]},
            "spec": args.get("spec", {"description": "Created via MCP"})
        })
    }
}


# ---- JSON-RPC MCP Endpoint (for client.py) ----
@app.post("/mcp")
async def mcp_entrypoint(req: Request):
    body = await req.json()
    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")

    if method == "tools/list":
        tools = [{"name": k, "description": v["description"]} for k, v in MCP_TOOLS.items()]
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}})

    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name not in MCP_TOOLS:
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id,
                                         "error": f"Unknown tool: {name}"})
        try:
            result = MCP_TOOLS[name]["handler"](args)
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": result})
        except Exception as e:
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "error": str(e)})

    return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "error": f"Unknown method: {method}"})

# ---- REST-style MCP Endpoints (from code 2) ----
@app.post("/mcp/list_applications")
async def list_applications(req: Request):
    data = await req.json()
    search = data.get("search")
    result = argocd_get("/applications", {"search": search} if search else None)
    return JSONResponse(content=result)

@app.post("/mcp/get_application")
async def get_application(req: Request):
    data = await req.json()
    app_name = data["applicationName"]
    result = argocd_get(f"/applications/{app_name}")
    return JSONResponse(content=result)

@app.post("/mcp/sync_application")
async def sync_application(req: Request):
    data = await req.json()
    app_name = data["applicationName"]
    result = argocd_post(f"/applications/{app_name}/sync")
    return JSONResponse(content=result)

@app.post("/mcp/create_application")
async def create_application(req: Request):
    data = await req.json()
    name = data.get("name")
    repo_url = data.get("repo_url")
    path = data.get("path")
    dest_ns = data.get("dest_ns", "default")
    sync_policy = data.get("sync_policy", "manual")

    payload = {
        "metadata": {"name": name},
        "spec": {
            "project": "default",
            "source": {
                "repoURL": repo_url,
                "path": path,
                "targetRevision": data.get("revision", "HEAD"),
            },
            "destination": {
                "server": "https://kubernetes.default.svc",
                "namespace": dest_ns,
            },
        },
    }
    if sync_policy == "automated":
        payload["spec"]["syncPolicy"] = {"automated": {}}

    result = argocd_post("/applications", payload)
    return JSONResponse(content=result)

# ---- Simple REST passthrough (for testing) ----
@app.get("/list-apps")
def list_apps():
    data = argocd_get("/applications")
    apps = []
    for item in data.get("items", []):
        name = item["metadata"]["name"]
        ns = item["metadata"]["namespace"]
        sync = item["status"].get("sync", {}).get("status", "Unknown")
        health = item["status"].get("health", {}).get("status", "Unknown")
        apps.append(f"- {name} (ns: {ns}, sync: {sync}, health: {health})")

    return {"message": "Applications in Argo CD:\n" + "\n".join(apps)}


# ---- Health check ----
@app.get("/health")
async def health():
    return {"status": "ok", "msg": "MCP server is running and connected to Argo CD"}
