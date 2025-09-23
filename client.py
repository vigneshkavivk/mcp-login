import os 
import json
import time
import re
from typing import Optional, Dict, Any, List
import requests
import streamlit as st
from dotenv import load_dotenv
from datetime import datetime, timezone

# Optional Gemini SDK
try:
    import google.generativeai as genai
except Exception:
    genai = None

# ---------------- CONFIG ----------------
load_dotenv()
API_URL = os.getenv("API_URL", "http://54.227.78.211:8080")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
GEMINI_AVAILABLE = False

if genai and GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        GEMINI_AVAILABLE = True
    except Exception:
        GEMINI_AVAILABLE = False

# ---------------- SERVERS ----------------
def load_servers_from_file() -> List[Dict[str, Any]]:
    """Load servers list from servers.json or fallback to sensible defaults."""
    try:
        with open("servers.json", "r") as f:
            data = json.load(f)
            servers = data.get("servers") or data.get("Servers") or []
            if isinstance(servers, list) and len(servers) > 0:
                return servers
    except Exception:
        pass
    # Fallback defaults
    return [
        {"name": "jenkins", "url": f"{API_URL}/mcp", "description": "Jenkins"},
        {"name": "kubernetes", "url": f"{API_URL}/mcp", "description": "Kubernetes"},
        {"name": "argocd", "url": f"{API_URL}/mcp", "description": "ArgoCD"},
    ]

SERVERS = load_servers_from_file()
SERVER_NAMES = [s.get("name") for s in SERVERS]

# ---------------- GATEWAY UTIL ----------------
def gateway_call(target: str,
                 method: str,
                 params: Optional[Dict[str, Any]] = None,
                 session_id: Optional[str] = None,
                 timeout: int = 20) -> Dict[str, Any]:
    """
    Call API_URL/mcp?target=<target> with JSON-RPC body.
    Adds session_id in the body when provided.
    """
    url = f"{API_URL}/mcp?target={target}"
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {}
    }
    if session_id:
        body["session_id"] = session_id
    try:
        r = requests.post(url, json=body, timeout=timeout)
        try:
            return r.json()
        except Exception:
            return {"error": f"Non-JSON response", "text": r.text, "status_code": r.status_code}
    except Exception as e:
        return {"error": str(e)}

# ---------------- MCP (legacy) CALL ----------------
def call_mcp_direct(server_url: str, method: str, params: Optional[Dict[str, Any]] = None, timeout:int=20):
    """Generic JSON-RPC POST to a server URL (used for listing tools if needed)."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    try:
        res = requests.post(server_url, json=payload, headers=headers, timeout=timeout)
        res.raise_for_status()
        text = res.text or ""
        # SSE-ish handling
        if text.startswith("event:") or "data:" in text:
            for line in text.splitlines():
                if line.strip().startswith("data:"):
                    txt = line.strip()[len("data:"):].strip()
                    try:
                        return json.loads(txt)
                    except Exception:
                        return {"result": txt}
        try:
            return res.json()
        except Exception:
            return {"result": res.text}
    except Exception as e:
        return {"error": str(e)}

# ---------------- HELPERS ----------------
def sanitize_args(args: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not args:
        return {}
    fixed = dict(args)
    if "resource" in fixed and "resourceType" not in fixed:
        fixed["resourceType"] = fixed.pop("resource")
    if fixed.get("resourceType") == "pods" and "namespace" not in fixed:
        fixed["namespace"] = "default"
    if fixed.get("namespace") == "all":
        fixed["allNamespaces"] = True
        fixed.pop("namespace", None)
    # Handle "all resources" request (from code-2)
    if fixed.get("resourceType") == "all":
        fixed["allResources"] = True
        fixed.pop("resourceType", None)
    # Handle common Kubernetes resource types (from code-2)
    resource_mappings = {
        "ns": "namespaces",
        "pod": "pods",
        "node": "nodes",
        "deploy": "deployments",
        "svc": "services",
        "cm": "configmaps",
        "secret": "secrets",
        "all": "all"
    }
    if fixed.get("resourceType") in resource_mappings:
        fixed["resourceType"] = resource_mappings[fixed["resourceType"]]
    return fixed

def _extract_json_from_text(text: str) -> Optional[dict]:
    try:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start:end])
    except Exception:
        pass
    return None

# ---------------- SERVER DETECTION (from code-2) ----------------
def detect_server_from_query(query: str, available_servers: list) -> Optional[Dict[str, Any]]:
    """Automatically detect which server to use based on query content."""
    query_lower = query.lower()
    # Check each server's tools to see which one matches the query
    for server in available_servers:
        try:
            tools = list_mcp_tools_for_server(server["name"])
            tool_names = [t.lower() for t in tools]
            # Check if any tool name is mentioned in the query
            for tool_name in tool_names:
                if tool_name in query_lower:
                    return server
            # Check for common keywords that match server types
            server_name = server["name"].lower()
            # Kubernetes queries
            if (("kubernetes" in query_lower or "k8s" in query_lower or 
                 "pod" in query_lower or "namespace" in query_lower or
                 "deployment" in query_lower or "service" in query_lower or
                 "secret" in query_lower or "configmap" in query_lower or
                 "node" in query_lower or "cluster" in query_lower or
                 "resource" in query_lower) and 
                ("kubernetes" in server_name or "k8s" in server_name)):
                return server
            # Jenkins queries
            if (("jenkins" in query_lower or "job" in query_lower or 
                 "build" in query_lower or "pipeline" in query_lower) and 
                "jenkins" in server_name):
                return server
            # ArgoCD queries
            if (("argocd" in query_lower or "application" in query_lower or 
                 "gitops" in query_lower or "sync" in query_lower) and 
                "argocd" in server_name):
                return server
        except Exception:
            continue
    # If no specific server detected, return the first available one
    return available_servers[0] if available_servers else None

# ---------------- GET ALL RESOURCES (from code-2) ----------------
def get_all_cluster_resources(server_url: str):
    """Get all resources in the cluster by querying multiple resource types."""
    resource_types = [
        "pods", "services", "deployments", "configmaps", 
        "secrets", "namespaces", "nodes"
    ]
    all_resources = {}
    for resource_type in resource_types:
        try:
            response = call_tool(server_url, "kubectl_get", {
                "resourceType": resource_type,
                "allNamespaces": True
            })
            if response and not response.get("error"):
                result = response.get("result", {})
                if isinstance(result, dict) and "items" in result:
                    all_resources[resource_type] = result["items"]
                else:
                    all_resources[resource_type] = result
            else:
                all_resources[resource_type] = f"Error: {response.get('error', 'Unknown error')}"
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        except Exception as e:
            all_resources[resource_type] = f"Exception: {str(e)}"
    return all_resources

# ---------------- TOOL CALL (from code-2, adapted for gateway) ----------------
def call_tool(server_name: str, name: str, arguments: dict, session_id: str):
    """Execute MCP tool by name with arguments via gateway."""
    if not name or not isinstance(arguments, dict):
        return {"error": "Invalid tool name or arguments"}
    rpc_params = {"name": name, "arguments": arguments}
    return gateway_call(target=server_name, method="tools/call", params=rpc_params, session_id=session_id, timeout=30)

# ---------------- LIST TOOLS (adapted from code-1) ----------------
def list_mcp_tools_for_server(server_name: str) -> List[str]:
    """Attempt to list tools by calling gateway tools/list on that server name."""
    try:
        resp = gateway_call(target=server_name, method="tools/list", params={}, session_id=None, timeout=10)
        result = resp.get("result")
        if isinstance(result, dict):
            tools = result.get("tools") or []
        elif isinstance(result, list):
            tools = result
        else:
            tools = []
        names = []
        for t in tools:
            if isinstance(t, dict) and t.get("name"):
                names.append(t["name"])
            elif isinstance(t, str):
                names.append(t)
        return names
    except Exception:
        return []

# ---------------- GEMINI: pick tool + args (from code-2, adapted) ----------------
def ask_gemini_for_tool_decision(query: str, server_name: str, retries: int = 2) -> Dict[str, Any]:
    """
    Use Gemini (if available) to map user query to {"tool":..., "args":..., "explanation":...}.
    Fallback: simple heuristic mapping.
    """
    # gather candidate tools for the server
    available_tools = list_mcp_tools_for_server(server_name)

    # basic heuristic fallback (no Gemini)
    def heuristic():
        q = query.lower()
        candidate = {"tool": None, "args": {}, "explanation": "Used local heuristic fallback."}
        # common command->tool mapping
        if "application" in q or "app" in q:
            candidate["tool"] = "list_applications"
        elif "pod" in q:
            candidate["tool"] = "list_pods"
        elif "job" in q or "jenkins" in q:
            candidate["tool"] = "list_jobs"
        elif "nodes" in q or "cluster size" in q or "how many nodes" in q:
            candidate["tool"] = "kubectl_get"
            candidate["args"] = {"resourceType": "nodes", "format": "json"}
        elif "all resources" in q or "everything" in q or "all" in q:
            candidate["tool"] = "kubectl_get"
            candidate["args"] = {"resourceType": "all", "allNamespaces": True}
        else:
            candidate["tool"] = "echo"
        return candidate

    if not GEMINI_AVAILABLE:
        return heuristic()

    # Build instruction for Gemini
    instruction = f"""
You are an assistant that maps a user's query to a tool name and args.
User query: "{query}"
Available tools for server '{server_name}': {json.dumps(available_tools, indent=2)}
Rules:
- Only choose tools from the available list above.
- Respond in strict JSON: {{"tool": "<tool_name_or_null>", "args": {{...}} | null, "explanation": "short"}}
If unsure, set tool to null.
"""
    for attempt in range(retries):
        try:
            model = genai.GenerativeModel(GEMINI_MODEL)
            resp = model.generate_content(instruction)
            text = getattr(resp, "text", str(resp)).strip()
            parsed = None
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = _extract_json_from_text(text)
            if not isinstance(parsed, dict):
                # try heuristic if parsing fails
                return heuristic()
            # sanitize
            parsed["args"] = sanitize_args(parsed.get("args") or {})
            # validate tool exists
            tool = parsed.get("tool")
            if tool and tool not in available_tools:
                parsed["explanation"] = f"Tool '{tool}' not available on server '{server_name}'."
                parsed["tool"] = None
            return parsed
        except Exception:
            time.sleep(1)
            continue
    return heuristic()

# ---------------- GEMINI: friendly answer (from code-2, adapted) ----------------
def ask_gemini_answer(user_input: str, raw_response: dict) -> str:
    """Ask Gemini to turn raw MCP/gateway response into human-friendly answer (fallback if unavailable)."""
    if not GEMINI_AVAILABLE:
        return generate_fallback_answer(user_input, raw_response)
    try:
        context_notes = ""
        if "last_known_cluster_name" in st.session_state:
            context_notes += f"\nPreviously known cluster: {st.session_state['last_known_cluster_name']}"
        if "last_known_cluster_size" in st.session_state:
            context_notes += f"\nPreviously known cluster size: {st.session_state['last_known_cluster_size']}"

        prompt = (
            f"User asked: {user_input}\n"
            f"Context: {context_notes}\n"
            f"Raw system response:\n{json.dumps(raw_response, indent=2)}\n"
            "INSTRUCTIONS:\n"
            "- Respond in clear, natural, conversational English.\n"
            "- If it's a list, format with bullet points.\n"
            "- If it's status, explain health and issues clearly.\n"
            "- If error occurred, DO NOT show raw error. Politely explain what went wrong and suggest what user can do.\n"
            "- If cluster name or size was inferred, mention that explicitly.\n"
            "- If cluster size = 1, say: 'This appears to be a minimal/single-node cluster.'\n"
            "- NEVER show JSON, code, or internal errors to user unless asked.\n"
            "- Be helpful, friendly, and precise.\n"
        )
        model = genai.GenerativeModel(GEMINI_MODEL)
        resp = model.generate_content(prompt)
        answer = getattr(resp, "text", str(resp)).strip()
        # try to extract cluster info
        extract_and_store_cluster_info(user_input, answer)
        return answer
    except Exception:
        return generate_fallback_answer(user_input, raw_response)

def generate_fallback_answer(user_input: str, raw_response: dict) -> str:
    """Generate human-friendly answer without Gemini (enhanced from code-2)."""
    if "error" in raw_response:
        error_msg = raw_response["error"]
        if "cluster" in user_input.lower():
            return "I couldn't retrieve the cluster information right now. Please check if the MCP server is running and accessible."
        return f"Sorry, I encountered an issue: {error_msg}"

    result = raw_response.get("result", {})

    # Handle different response formats
    if isinstance(result, dict):
        # Kubernetes-style responses with items
        if "items" in result:
            items = result["items"]
            count = len(items)
            if "node" in user_input.lower() or "cluster size" in user_input.lower():
                if count == 1:
                    node_name = items[0].get("metadata", {}).get("name", "unknown")
                    return f"This is a single-node cluster. The node is named: {node_name}"
                else:
                    return f"The cluster has {count} nodes."
            if "namespace" in user_input.lower():
                namespaces = [item.get("metadata", {}).get("name", "unnamed") for item in items]
                if namespaces:
                    return f"Found {count} namespaces:\n" + "\n".join([f"• {ns}" for ns in namespaces])
                else:
                    return "No namespaces found."
            if "pod" in user_input.lower():
                pods = [
                    f"{item.get('metadata', {}).get('name', 'unnamed')} in {item.get('metadata', {}).get('namespace', 'default')} namespace"
                    for item in items
                ]
                if pods:
                    return f"Found {count} pods:\n" + "\n".join([f"• {pod}" for pod in pods])
                else:
                    return "No pods found."
            if "secret" in user_input.lower():
                secrets = [
                    f"{item.get('metadata', {}).get('name', 'unnamed')} in {item.get('metadata', {}).get('namespace', 'default')} namespace"
                    for item in items
                ]
                if secrets:
                    return f"Found {count} secrets:\n" + "\n".join([f"• {secret}" for secret in secrets])
                else:
                    return "No secrets found."

        # Jenkins-style responses
        if "jobs" in result:
            jobs = result["jobs"]
            if jobs:
                return f"Found {len(jobs)} Jenkins jobs:\n" + "\n".join([f"• {job.get('name', 'unnamed')}" for job in jobs])
            else:
                return "No Jenkins jobs found."

        # ArgoCD-style responses
        if "applications" in result:
            apps = result["applications"]
            if apps:
                return f"Found {len(apps)} ArgoCD applications:\n" + "\n".join([f"• {app.get('name', 'unnamed')}" for app in apps])
            else:
                return "No ArgoCD applications found."

    # Generic fallback
    if result:
        return f"Operation completed successfully. Result: {json.dumps(result, indent=2)}"
    return "Operation completed successfully, but no data was returned."


def extract_and_store_cluster_info(user_input: str, answer: str):
    """Heuristics to extract cluster name/size from Gemini's answer text (from code-2)."""
    try:
        # Extract cluster name
        if "cluster name" in user_input.lower():
            patterns = [
                r"cluster[^\w]*([\w-]+)",
                r"name[^\w][:\-]?[^\w]([\w-]+)",
            ]
            for pattern in patterns:
                match = re.search(pattern, answer, re.IGNORECASE)
                if match:
                    cluster_name = match.group(1).strip()
                    st.session_state["last_known_cluster_name"] = cluster_name
                    break

        # Extract cluster size
        if "cluster size" in user_input.lower() or "how many nodes" in user_input.lower():
            numbers = re.findall(r'\b\d+\b', answer)
            if numbers:
                st.session_state["last_known_cluster_size"] = int(numbers[0])
    except Exception:
        pass


# ---------------- AUTH (login) ----------------
def attempt_login(username: str, password: str) -> Dict[str, Any]:
    try:
        r = requests.post(f"{API_URL}/login", json={"username": username, "password": password}, timeout=10)
        if r.status_code == 200:
            return r.json()
        try:
            return {"error": r.json()}
        except Exception:
            return {"error": r.text}
    except Exception as e:
        return {"error": str(e)}


# ---------------- STREAMLIT APP ----------------
def main():
    st.set_page_config(page_title="MCP Chat Assistant", page_icon="⚡", layout="wide")
    st.title("🤖 MaSaOps Bot (Merged)")

    # session defaults
    if "session" not in st.session_state:
        st.session_state.session = None
        st.session_state.username = None
        st.session_state.access = []
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "last_known_cluster_name" not in st.session_state:
        st.session_state["last_known_cluster_name"] = None
    if "last_known_cluster_size" not in st.session_state:
        st.session_state["last_known_cluster_size"] = None
    if "available_servers" not in st.session_state:
        st.session_state["available_servers"] = SERVERS

    # Sidebar: profile, settings
    with st.sidebar:


        st.header("👤 Profile")
        if st.session_state.session:
            st.write(f"**Username:** {st.session_state.username}")
            st.write(f"**Access:** {', '.join(st.session_state.access) if st.session_state.access else 'None'}")
            if st.button("Logout"):
                st.session_state.session = None
                st.session_state.username = None
                st.session_state.access = []
                st.rerun()
        else:
            st.write("Not logged in")

        st.title("⚙ Settings")
        st.markdown("**Providers & Keys**")
        st.text_input("Gemini API Key (env)", value=(GEMINI_API_KEY or ""), disabled=True)
        models = [GEMINI_MODEL, "gemini-1.0", "gemini-1.5-pro", "gemini-2.0-flash"]
        sel = st.selectbox("Gemini model", options=models, index=0)
        st.session_state["gemini_model"] = sel


        if st.button("Clear chat history"):
            st.session_state["messages"] = []
            st.rerun()

    # If not logged in -> show login form
    if not st.session_state.session:
        st.subheader("Login")
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login", key="login_btn"):
            resp = attempt_login(username, password)
            if resp and resp.get("session_id"):
                st.session_state.session = resp.get("session_id")
                st.session_state.username = resp.get("username") or username
                st.session_state.access = resp.get("access", []) or []
                st.success(f"Logged in as {st.session_state.username}.")
                # seed a welcome message
                access_str = ", ".join(st.session_state.access)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"Welcome {st.session_state.username}! Ask me about {access_str}."
                })
                st.rerun()
            else:
                st.error(f"Login failed: {resp.get('error') if resp else 'unknown error'}")
        st.info("This app requires a working API_URL login endpoint that returns JSON with session_id and access list.")
        return  # stop rendering rest until logged in

    # Chat UI
    st.subheader("What's on your mind today? 🤔")

    # Render chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg.get("role", "assistant")):
            st.markdown(msg.get("content", ""))

    user_prompt = st.chat_input("Ask anything about MCP (e.g., list pods, list applications, cluster size...)")
    if not user_prompt:
        return

    # append user message
    st.session_state.messages.append({"role": "user", "content": user_prompt})
    st.chat_message("user").markdown(user_prompt)

    # Auto-detect which server to use based on query (from code-2)
    with st.spinner("🔍 Finding the right server for your query..."):
        selected_server = detect_server_from_query(user_prompt, SERVERS)

    if not selected_server:
        error_msg = "No MCP servers available. Please check your servers.json file."
        st.session_state.messages.append({"role": "assistant", "content": error_msg})
        st.chat_message("assistant").error(error_msg)
        return

    chosen_server = selected_server.get("name")
    # Show which server we're using
    server_info = f"🤖 Using server: *{chosen_server}*"
    st.session_state.messages.append({"role": "assistant", "content": server_info})
    st.chat_message("assistant").markdown(server_info)

    # RBAC: ensure user has access to chosen_server
    if chosen_server not in st.session_state.access:
        # If user has wildcard or full access, allow; otherwise deny
        if "all" not in st.session_state.access and "admin" not in st.session_state.access:
            deny_msg = f"🚫 Access denied: your access list ({', '.join(st.session_state.access) or 'none'}) doesn't include {chosen_server}."
            st.session_state.messages.append({"role":"assistant","content":deny_msg})
            st.chat_message("assistant").markdown(deny_msg)
            return

    # Use Gemini (or heuristic) to pick tool + args (from code-2)
    with st.spinner("🤔 Analyzing your request..."):
        decision = ask_gemini_for_tool_decision(user_prompt, chosen_server)

    explanation = decision.get("explanation") or "Deciding how to help..."
    st.session_state.messages.append({"role": "assistant", "content": f"💡 {explanation}"})
    st.chat_message("assistant").markdown(f"💡 {explanation}")

    chosen_tool = decision.get("tool")
    tool_args = decision.get("args") or {}

    # If no tool chosen, offer suggestions
    if not chosen_tool:
        help_msg = (
            "I couldn't find a direct tool to answer your question. Try:\n"
            "- 'List pods in default namespace'\n"
            "- 'List argocd applications'\n"
            "- 'How many nodes in the cluster?'\n"
            "*For Kubernetes:*\n"
            "- \"List all namespaces\"\n"
            "- \"Show running pods\"\n"
            "- \"Get cluster nodes\"\n"
            "- \"Show all services\"\n"
            "- \"List all secrets\"\n"
            "- \"Show all resources in cluster\"\n"
            "*For Jenkins:*\n"
            "- \"List all jobs\"\n"
            "- \"Show build status\"\n"
            "*For ArgoCD:*\n"
            "- \"List applications\"\n"
            "- \"Show application status\"\n"
            "Or try being more specific about what you'd like to see!"
        )
        st.session_state.messages.append({"role":"assistant","content":help_msg})
        st.chat_message("assistant").markdown(help_msg)
        return

    # Show call summary
    st.chat_message("assistant").markdown(f"🔧 Calling `{chosen_tool}` on `{chosen_server}` with args:\n```json\n{json.dumps(tool_args, indent=2)}\n```")

    # Special handling for "all resources" request (from code-2)
    if (user_prompt.lower().strip() in ["show me all resources in cluster", "get all resources", "all resources"] or
        ("all" in user_prompt.lower() and "resource" in user_prompt.lower())):
        with st.spinner("🔄 Gathering all cluster resources (this may take a moment)..."):
            # For "all resources", we need to call the direct MCP endpoint, not the gateway.
            # We'll use the server's direct URL from the SERVERS list.
            server_url = next((s["url"] for s in SERVERS if s["name"] == chosen_server), None)
            if server_url:
                all_resources = get_all_cluster_resources(server_url)
                resp = {"result": all_resources}
            else:
                resp = {"error": f"Could not find URL for server {chosen_server}"}
    else:
        # Perform gateway call with session id
        resp = call_tool(chosen_server, chosen_tool, tool_args, st.session_state.session)

    # Smart fallbacks: if expecting cluster name and resp empty/error -> try nodes
    if ("cluster name" in user_prompt.lower()) and (not resp or resp.get("error")):
        st.chat_message("assistant").markdown("📌 Attempting to infer cluster name from nodes...")
        node_resp = gateway_call(
            target=chosen_server,
            method="tools/call",
            params={"name":"kubectl_get","arguments":{"resourceType":"nodes","format":"json"}},
            session_id=st.session_state.session,
            timeout=20
        )
        items = (node_resp.get("result") or {}).get("items") if isinstance(node_resp.get("result"), dict) else None
        if items and len(items) > 0:
            first_node = items[0].get("metadata", {}).get("name", "unknown")
            cluster_hint = first_node.split(".")[0] if "." in first_node else first_node
            st.session_state["last_known_cluster_name"] = cluster_hint
            resp = {"result": {"inferred_cluster_name": cluster_hint}}
            st.chat_message("assistant").markdown(f"✅ I inferred the cluster name: *{cluster_hint}*")

    # Smart cluster size handling
    if "cluster size" in user_prompt.lower() and chosen_tool == "kubectl_get" and tool_args.get("resourceType") == "nodes":
        if not resp.get("error") and isinstance(resp.get("result"), dict):
            items = resp["result"].get("items", [])
            node_count = len(items)
            st.session_state["last_known_cluster_size"] = node_count
            if node_count == 1:
                node_name = items[0].get("metadata", {}).get("name", "unknown")
                resp["result"]["_note"] = f"Single-node cluster. Node: {node_name}"

    # Turn raw response into friendly answer (Gemini or fallback)
    with st.spinner("📝 Formatting response..."):
        final_answer = ask_gemini_answer(user_prompt, resp)

    st.session_state.messages.append({"role":"assistant","content":final_answer})
    st.chat_message("assistant").markdown(final_answer)


# run app
if __name__ == "__main__":
    main()
