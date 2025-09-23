#!/usr/bin/env python3
"""
MasaBot Jenkins MCP Server (Merged)
----------------------------------
Single FastAPI app that provides:
- JSON-RPC MCP endpoint (/mcp) with tools/list and tools/call
- REST endpoints for Jenkins version, upgrade checks, plugin management,
  credentials management, restart, groovy script execution, health, etc.

Run:
    uvicorn merged_server:app --host 0.0.0.0 --port 8080
"""

import os
import json
import re
import subprocess
from typing import Optional, Dict, Any, List
import requests
from requests.auth import HTTPBasicAuth
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

# optionally suppress insecure request warnings if verify=False used
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables (adjust path as needed)
load_dotenv('config/server.env')

# ---- Config ----
JENKINS_URL = os.getenv("JENKINS_URL", "http://jenkins.example.com")
JENKINS_USER = os.getenv("JENKINS_USER", "admin")
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN", "changeme")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))

app = FastAPI(title="MasaBot Jenkins MCP Server - Unified")

# ---- MCP Tools JSON loader (fallbacks included) ----
def load_mcp_tools():
    try:
        with open("mcp_tools.json", "r") as f:
            data = json.load(f)
            return data.get("tools", [])
    except FileNotFoundError:
        # Fallback to a reasonable default tool list
        return [
            {
                "name": "list_jobs",
                "description": "List all Jenkins jobs",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "get_job",
                "description": "Get details of a specific Jenkins job",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Name of the Jenkins job"}},
                    "required": ["name"]
                }
            },
            {
                "name": "trigger_build",
                "description": "Trigger a Jenkins build (with or without parameters)",
                "inputSchema": {"type": "object", "properties": {"jobName": {"type": "string"}, "parameters": {"type": "object"}}, "required": ["jobName"]}
            },
            {
                "name": "get_build_info",
                "description": "Get build info for a job/build number",
                "inputSchema": {"type": "object", "properties": {"job_name": {"type": "string"}, "build_number": {"type": "integer"}}, "required": ["job_name", "build_number"]}
            }
        ]

MCP_TOOLS = load_mcp_tools()

# ---- Helpers ----
def jenkins_url(path: str) -> str:
    """Ensure path begins with '/' and join with JENKINS_URL"""
    if not path.startswith("/"):
        path = "/" + path
    return JENKINS_URL.rstrip("/") + path

def job_path(name: str) -> str:
    """
    Convert Jenkins job name to path segments:
    Supports foldered jobs like folder1/folder2/job-name -> job/folder1/job/folder2/job/job-name
    """
    return "/".join(f"job/{part}" for part in name.split("/"))

def job_api_path(name: str) -> str:
    """Return path with leading slash suitable for API calls to a job"""
    return "/" + job_path(name)

def jenkins_request(method: str, path: str, **kwargs) -> Dict[str, Any]:
    """
    Generic request helper that returns dict with parsed JSON if available,
    else text. Uses basic auth from env config. verify=False by default (to support self-signed)
    """
    url = jenkins_url(path)
    auth = HTTPBasicAuth(JENKINS_USER, JENKINS_TOKEN)
    try:
        if method.upper() == "GET":
            r = requests.get(url, auth=auth, timeout=REQUEST_TIMEOUT, verify=False, **kwargs)
        elif method.upper() == "POST":
            r = requests.post(url, auth=auth, timeout=REQUEST_TIMEOUT, verify=False, **kwargs)
        elif method.upper() == "PUT":
            r = requests.put(url, auth=auth, timeout=REQUEST_TIMEOUT, verify=False, **kwargs)
        elif method.upper() == "DELETE":
            r = requests.delete(url, auth=auth, timeout=REQUEST_TIMEOUT, verify=False, **kwargs)
        else:
            return {"error": f"Unsupported HTTP method: {method}"}

        r.raise_for_status()
        try:
            return {"status_code": r.status_code, "json": r.json(), "text": r.text, "headers": dict(r.headers)}
        except Exception:
            return {"status_code": r.status_code, "text": r.text, "headers": dict(r.headers)}
    except requests.exceptions.HTTPError as e:
        return {"error": str(e), "status_code": getattr(e.response, "status_code", None), "text": getattr(e.response, "text", None)}
    except Exception as e:
        return {"error": str(e)}

def jenkins_get(path: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> Dict[str, Any]:
    return jenkins_request("GET", path, params=params, headers=headers)

def jenkins_post(path: str, data: Optional[Any] = None, headers: Optional[dict] = None, params: Optional[dict] = None, files: Optional[Any] = None) -> Dict[str, Any]:
    return jenkins_request("POST", path, data=data, headers=headers, params=params, files=files)

# ---- Version compare helper ----
def compare_versions(version1: str, version2: str) -> int:
    """Compare dotted versions. Return -1 if v1<v2, 0 if equal, 1 if v1>v2"""
    def parts(v):
        # sanitize non-digit chars
        v = re.sub(r'[^0-9.]', '', str(v) or "0")
        return [int(x) for x in v.split('.') if x != '']
    v1 = parts(version1)
    v2 = parts(version2)
    # pad
    while len(v1) < len(v2):
        v1.append(0)
    while len(v2) < len(v1):
        v2.append(0)
    for a, b in zip(v1, v2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0

# ---- Tool Handlers (MCP) ----
def handle_list_jobs(args: Dict) -> Dict:
    data = jenkins_get("/api/json")
    jobs = []
    if isinstance(data, dict) and "json" in data and isinstance(data["json"], dict):
        for job in data["json"].get("jobs", []):
            jobs.append({
                "name": job.get("name"),
                "url": job.get("url"),
                "color": job.get("color", ""),
                "description": job.get("description", "")
            })
    return {"jobs": jobs, "raw": data}

def handle_get_job(args: Dict) -> Dict:
    name = args.get("name")
    if not name:
        return {"error": "name parameter is required"}
    return jenkins_get(f"{job_api_path(name)}/api/json")

def handle_create_job(args: Dict) -> Dict:
    name = args.get("name")
    config_xml = args.get("config_xml")
    if not name or not config_xml:
        return {"error": "name and config_xml parameters are required"}
    headers = {"Content-Type": "application/xml"}
    return jenkins_post(f"/createItem?name={name}", data=config_xml, headers=headers)

def handle_update_job(args: Dict) -> Dict:
    name = args.get("name")
    config_xml = args.get("config_xml")
    if not name or not config_xml:
        return {"error": "name and config_xml parameters are required"}
    headers = {"Content-Type": "application/xml"}
    # Use job config endpoint (POST to /job/.../config.xml)
    return jenkins_post(f"{job_api_path(name)}/config.xml", data=config_xml, headers=headers)

def handle_delete_job(args: Dict) -> Dict:
    name = args.get("name")
    if not name:
        return {"error": "name parameter is required"}
    return jenkins_post(f"{job_api_path(name)}/doDelete")

def handle_disable_job(args: Dict) -> Dict:
    name = args.get("name")
    if not name:
        return {"error": "name parameter is required"}
    return jenkins_post(f"{job_api_path(name)}/disable")

def handle_enable_job(args: Dict) -> Dict:
    name = args.get("name")
    if not name:
        return {"error": "name parameter is required"}
    return jenkins_post(f"{job_api_path(name)}/enable")

def handle_rename_job(args: Dict) -> Dict:
    current_name = args.get("current_name")
    new_name = args.get("new_name")
    if not current_name or not new_name:
        return {"error": "current_name and new_name parameters are required"}
    return jenkins_post(f"{job_api_path(current_name)}/doRename?newName={new_name}")

def handle_trigger_build(args: Dict) -> Dict:
    job_name = args.get("jobName") or args.get("job_name")
    parameters = args.get("parameters", {})
    if not job_name:
        return {"error": "jobName parameter is required"}
    if parameters:
        # buildWithParameters via POST with params
        return jenkins_post(f"{job_api_path(job_name)}/buildWithParameters", params=parameters)
    else:
        return jenkins_post(f"{job_api_path(job_name)}/build")

def handle_stop_build(args: Dict) -> Dict:
    job_name = args.get("jobName") or args.get("job_name")
    build_number = args.get("buildNumber") or args.get("build_number")
    if not job_name or build_number is None:
        return {"error": "jobName and buildNumber parameters are required"}
    return jenkins_post(f"{job_api_path(job_name)}/{build_number}/stop")

def handle_get_build_info(args: Dict) -> Dict:
    job_name = args.get("job_name") or args.get("jobName")
    build_number = args.get("build_number") or args.get("buildNumber")
    if not job_name or build_number is None:
        return {"error": "job_name and build_number parameters are required"}
    return jenkins_get(f"{job_api_path(job_name)}/{build_number}/api/json")

def handle_get_build_logs(args: Dict) -> Dict:
    job_name = args.get("job_name") or args.get("jobName")
    build_number = args.get("build_number") or args.get("buildNumber")
    if not job_name or build_number is None:
        return {"error": "job_name and build_number parameters are required"}
    return jenkins_get(f"{job_api_path(job_name)}/{build_number}/consoleText")

def handle_get_job_config(args: Dict) -> Dict:
    name = args.get("name")
    if not name:
        return {"error": "name parameter is required"}
    return jenkins_get(f"{job_api_path(name)}/config.xml")

def handle_update_job_config(args: Dict) -> Dict:
    name = args.get("name")
    config_xml = args.get("config_xml")
    if not name or not config_xml:
        return {"error": "name and config_xml parameters are required"}
    headers = {"Content-Type": "application/xml"}
    return jenkins_post(f"{job_api_path(name)}/config.xml", data=config_xml, headers=headers)

# ---- Tool registry used by MCP JSON-RPC ----
TOOL_HANDLERS = {
    "list_jobs": handle_list_jobs,
    "get_job": handle_get_job,
    "create_job": handle_create_job,
    "update_job": handle_update_job,
    "delete_job": handle_delete_job,
    "disable_job": handle_disable_job,
    "enable_job": handle_enable_job,
    "rename_job": handle_rename_job,
    "trigger_build": handle_trigger_build,
    "stop_build": handle_stop_build,
    "get_build_info": handle_get_build_info,
    "get_build_logs": handle_get_build_logs,
    "get_job_config": handle_get_job_config,
    "update_job_config": handle_update_job_config
}

# ---- Helper for Groovy scripts (used by plugin updates etc.) ----
def _run_groovy_script(script: str) -> Dict[str, Any]:
    """
    Execute a Groovy script via the script console (/script).
    Returns dict similar to jenkins_post output.
    Requires that the Jenkins user has permission to run script console.
    """
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"script": script}
    return jenkins_post("/script", data=data, headers=headers)

# ---- JSON-RPC MCP Endpoint (/mcp) ----
@app.post("/mcp")
async def mcp_entrypoint(req: Request):
    """JSON-RPC MCP endpoint"""
    try:
        body = await req.json()
    except Exception as e:
        return JSONResponse(content={"jsonrpc": "2.0", "id": 1, "error": {"code": -32700, "message": f"Parse error: {str(e)}"}}, status_code=400)

    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id", 1)

    if method == "tools/list":
        return JSONResponse(content={
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": MCP_TOOLS}
        })

    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {}) or {}
        if not name:
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Missing tool name in params"}})
        if name not in TOOL_HANDLERS:
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {name}"}})
        try:
            result = TOOL_HANDLERS[name](arguments)
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": result})
        except Exception as e:
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": f"Tool execution error: {str(e)}"}})

    else:
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})

# ---- REST: Jenkins Version & Upgrade Endpoints ----
@app.get("/mcp/get_jenkins_version")
def get_jenkins_version():
    """
    Get Jenkins version (tries HEAD for X-Jenkins header, falls back to /api/json).
    """
    try:
        r = requests.head(jenkins_url("/"), auth=HTTPBasicAuth(JENKINS_USER, JENKINS_TOKEN), timeout=REQUEST_TIMEOUT, verify=False)
        version = r.headers.get("X-Jenkins")
        if version:
            return {"version": version, "headers": dict(r.headers)}
    except Exception:
        pass

    data = jenkins_get("/api/json")
    headers = data.get("headers") if isinstance(data, dict) else {}
    version = headers.get("X-Jenkins") if headers else None
    return {"version": version or "unknown", "jenkins_root": data}

@app.get("/mcp/check_jenkins_upgrade")
def check_jenkins_upgrade():
    """
    Check for newer Jenkins core versions in the update center.
    """
    cur = get_jenkins_version().get("version", "unknown")
    update_center = jenkins_get("/updateCenter/api/json")
    if "error" in update_center:
        return {"error": "Failed to get update center data", "current_version": cur}
    payload = update_center.get("json") or update_center
    # availableVersions is usually present under 'core' or root; try common locations
    possible = payload.get("availableCoreVersions") or payload.get("availableVersions") or []
    latest_version = "0.0.0"
    for version in possible:
        if compare_versions(version, latest_version) > 0:
            latest_version = version
    upgrade_available = compare_versions(latest_version, cur) > 0
    return {"current_version": cur, "latest_version": latest_version, "upgrade_available": upgrade_available, "available_versions": possible}

@app.post("/mcp/upgrade_jenkins")
def upgrade_jenkins():
    """
    Trigger Jenkins upgrade by downloading WAR and replacing. This runs a local script with sudo.
    Use with caution.
    """
    info = check_jenkins_upgrade()
    if not info.get("upgrade_available"):
        return {"message": "No Jenkins upgrade available", "status": "error", "current_version": info.get("current_version")}
    latest = info.get("latest_version")
    script = f"""#!/bin/bash
set -e
echo "Stopping Jenkins..."
sudo systemctl stop jenkins
echo "Backing up Jenkins home..."
sudo cp -a /var/lib/jenkins /var/lib/jenkins.bak.$(date +%s)
echo "Downloading Jenkins WAR {latest}..."
wget https://updates.jenkins.io/download/war/{latest}/jenkins.war -O /tmp/jenkins.war
echo "Replacing WAR..."
sudo cp /tmp/jenkins.war /usr/share/jenkins/jenkins.war
echo "Starting Jenkins..."
sudo systemctl start jenkins
echo "Done"
"""
    script_path = "/tmp/masabot_jenkins_upgrade.sh"
    with open(script_path, "w") as f:
        f.write(script)
    subprocess.run(["chmod", "+x", script_path])
    try:
        subprocess.run(["sudo", script_path], check=True)
        return {"message": f"Jenkins upgraded to {latest}", "status": "success", "script_path": script_path}
    except subprocess.CalledProcessError as e:
        return {"message": "Upgrade script failed", "status": "failed", "script_path": script_path, "error": str(e)}

# ---- REST: Plugins Management ----
@app.get("/mcp/plugins_installed")
def plugins_installed():
    data = jenkins_get("/pluginManager/api/json?depth=1")
    if "error" in data:
        return JSONResponse(content=data, status_code=500)
    payload = data.get("json") or data
    plugins = []
    for p in payload.get("plugins", []):
        plugins.append({
            "shortName": p.get("shortName"),
            "version": p.get("version"),
            "active": p.get("active"),
            "enabled": p.get("enabled"),
            "hasUpdate": p.get("hasUpdate"),
            "url": p.get("url"),
        })
    return {"installed_plugins": plugins}

@app.get("/mcp/plugins_available")
def plugins_available(limit: Optional[int] = 200):
    data = jenkins_get("/updateCenter/api/json")
    if "error" in data:
        return JSONResponse(content=data, status_code=500)
    payload = data.get("json") or data
    center_plugins = payload.get("plugins") or {}
    plugins = []
    if isinstance(center_plugins, dict):
        for idx, (k, v) in enumerate(center_plugins.items()):
            if idx >= limit:
                break
            plugins.append({
                "name": k,
                "version": v.get("version"),
                "title": v.get("title"),
                "excerpt": v.get("excerpt"),
                "requiredCore": v.get("requiredCore"),
            })
    elif isinstance(center_plugins, list):
        for idx, v in enumerate(center_plugins):
            if idx >= limit:
                break
            plugins.append({
                "name": v.get("name") or v.get("id"),
                "version": v.get("version"),
                "title": v.get("title"),
                "excerpt": v.get("excerpt"),
                "requiredCore": v.get("requiredCore"),
            })
    return {"available_plugins_sample": plugins, "count": len(plugins)}

@app.get("/mcp/list_plugins_with_updates")
def list_plugins_with_updates():
    data = jenkins_get("/pluginManager/api/json?depth=1")
    if "error" in data:
        return JSONResponse(content=data, status_code=500)
    installed_plugins = []
    for p in data.get("json", {}).get("plugins", []):
        if p.get("hasUpdate", False):
            installed_plugins.append({
                "shortName": p.get("shortName"),
                "version": p.get("version"),
                "latestVersion": p.get("latestVersion"),
                "url": p.get("url"),
                "hasUpdate": p.get("hasUpdate")
            })
    return {"plugins_with_updates": installed_plugins}

@app.post("/mcp/update_all_plugins")
def update_all_plugins():
    data = jenkins_get("/pluginManager/api/json?depth=1")
    if "error" in data:
        return JSONResponse(content=data, status_code=500)
    installed_plugins = []
    for p in data.get("json", {}).get("plugins", []):
        if p.get("hasUpdate", False) and p.get("shortName"):
            installed_plugins.append(p.get("shortName"))
    if not installed_plugins:
        return {"message": "No plugins need updating"}
    result = []
    for plugin in installed_plugins:
        groovy = f"""
import jenkins.model.*
def pm = Jenkins.instance.pluginManager
def p = pm.getPlugin('{plugin}')
if (p != null) {{
    p.deploy()
    println('{plugin} deploy requested')
}} else {{
    println('{plugin} not found')
}}
"""
        res = _run_groovy_script(groovy)
        result.append(res.get("text", res))
    return {"result": result, "message": "Plugin update requests submitted (check Jenkins for progress)"}

@app.get("/mcp/check_plugin_compatibility")
def check_plugin_compatibility(plugin_id: str, jenkins_version: Optional[str] = None):
    if not jenkins_version:
        jenkins_version = get_jenkins_version().get("version", "unknown")
    # Simplified heuristic
    if compare_versions(jenkins_version, "2.387.1") >= 0:
        return {"compatible": True, "message": f"Plugin {plugin_id} is likely compatible with Jenkins {jenkins_version}"}
    else:
        return {"compatible": False, "message": f"Plugin {plugin_id} likely requires Jenkins >= 2.387.1"}

# ---- REST: Credentials Management ----
@app.get("/mcp/list_credentials")
def list_credentials():
    data = jenkins_get("/credentials/store/system/domain/_/api/json?tree=credentials[id,description]")
    creds = []
    if isinstance(data, dict):
        j = data.get("json") or data
        for c in j.get("credentials", []) if isinstance(j.get("credentials", []), list) else []:
            creds.append({"id": c.get("id"), "description": c.get("description", "")})
    return {"credentials": creds}

@app.post("/mcp/create_credential")
async def create_credential(req: Request):
    """
    Create credentials in the system store.
    Expects form-data with a 'json' field containing the credential JSON string
    Example JSON:
    {
      "id": "my-id",
      "kind": "usernamePassword",
      "username": "user",
      "password": "pass",
      "scope": "GLOBAL"
    }
    """
    form_data = await req.form()
    json_str = form_data.get("json")
    if not json_str:
        raise HTTPException(status_code=400, detail="Missing 'json' form field")
    try:
        cred = json.loads(json_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    if not cred.get("id"):
        raise HTTPException(status_code=400, detail="id is required")
    valid_scopes = ["GLOBAL", "SYSTEM", "ITEM"]
    if cred.get("scope") not in valid_scopes:
        raise HTTPException(status_code=400, detail=f"Invalid scope. Must be one of: {', '.join(valid_scopes)}")
    if cred.get("kind") == "usernamePassword":
        if cred.get("username") is None or cred.get("password") is None:
            raise HTTPException(status_code=400, detail="username and password are required for usernamePassword kind")
        credential_data = {
            "scope": cred.get("scope"),
            "id": cred.get("id"),
            "username": cred.get("username"),
            "password": cred.get("password"),
            "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
        }
    elif cred.get("kind") in ("secretText", "string"):
        if cred.get("secret") is None:
            raise HTTPException(status_code=400, detail="secret is required for secretText/string kind")
        credential_data = {
            "scope": cred.get("scope"),
            "id": cred.get("id"),
            "secret": cred.get("secret"),
            "$class": "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl"
        }
    else:
        raise HTTPException(status_code=400, detail=f"unsupported kind: {cred.get('kind')}")
    payload = {"": "0", "credentials": credential_data}
    form_payload = {"json": json.dumps(payload)}
    try:
        r = requests.post(
            jenkins_url("/credentials/store/system/domain/_/createCredentials"),
            auth=HTTPBasicAuth(JENKINS_USER, JENKINS_TOKEN),
            data=form_payload,
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"request failed: {str(e)}")
    if r.status_code in (200, 201):
        return {"message": f"Credential {cred['id']} created", "status_code": r.status_code, "text": r.text}
    else:
        raise HTTPException(status_code=r.status_code, detail=r.text)

@app.delete("/mcp/delete_credential")
def delete_credential(id: str):
    try:
        credential_data = jenkins_get(f"/credentials/store/system/domain/_/credential/{id}/api/json")
        if "error" in credential_data or not credential_data.get("json", {}).get("id"):
            raise HTTPException(status_code=404, detail="Credential not found")
        r = requests.post(
            jenkins_url(f"/credentials/store/system/domain/_/credential/{id}/doDelete"),
            auth=HTTPBasicAuth(JENKINS_USER, JENKINS_TOKEN),
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"request failed: {str(e)}")
    if r.status_code in (200, 201):
        return {"status": "success", "message": f"Credential '{id}' deleted successfully"}
    else:
        raise HTTPException(status_code=r.status_code, detail=r.text)

# ---- Restart Endpoint ----
@app.post("/mcp/restart")
def jenkins_restart(mode: Optional[str] = "safe"):
    """
    Trigger a Jenkins restart:
    mode = 'safe' -> safeRestart
    mode = 'restart' -> restart
    """
    try:
        if mode == "safe":
            r = requests.post(jenkins_url("/safeRestart"), auth=HTTPBasicAuth(JENKINS_USER, JENKINS_TOKEN), timeout=REQUEST_TIMEOUT, verify=False)
        else:
            r = requests.post(jenkins_url("/restart"), auth=HTTPBasicAuth(JENKINS_USER, JENKINS_TOKEN), timeout=REQUEST_TIMEOUT, verify=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"request failed: {str(e)}")
    if r.status_code in (200, 201, 302):
        return {"message": f"Jenkins {mode} requested", "status_code": r.status_code}
    else:
        raise HTTPException(status_code=r.status_code, detail=r.text)

# ---- Health & Root ----
@app.get("/health")
async def health():
    root = jenkins_get("/api/json")
    ok = isinstance(root, dict) and (("json" in root and ("jobs" in root["json"] or "version" in root["json"])) or ("jobs" in root if isinstance(root, dict) else False))
    return {"status": "ok" if ok else "error", "jenkins": root}

@app.get("/")
def root():
    return {"msg": "MasaBot Jenkins MCP server running. Use /mcp endpoint for JSON-RPC and /mcp/* for REST endpoints."}

