#!/usr/bin/env python3
# client.py
import os
import json
import time
import re
import requests
import streamlit as st
from dotenv import load_dotenv
from typing import Optional, Dict, Any

# Optional Gemini SDK
try:
    import google.generativeai as genai
except Exception:
    genai = None

# ---------------- CONFIG ----------------
load_dotenv()
API_URL = os.getenv("API_URL", "http://54.227.78.211:8080")   # auth_gateway.py endpoint
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Configure Gemini
GEMINI_AVAILABLE = False
if GEMINI_API_KEY and genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        GEMINI_AVAILABLE = True
    except Exception:
        GEMINI_AVAILABLE = False

# Load servers list from servers.json
def load_servers() -> list:
    try:
        with open("servers.json") as f:
            data = json.load(f)
        return data.get("servers", [])
    except Exception:
        return []

SERVERS = load_servers()

# Initialize session state
if "messages" not in st.session_state:
    st.session_state.messages = []
    st.session_state.last_known_cluster_name = None
    st.session_state.last_known_cluster_size = None
    st.session_state.available_servers = SERVERS

# ---------------- HELPERS ----------------
def api_post(path: str, payload: dict, target: Optional[str] = None) -> Dict[str, Any]:
    """Wrapper to POST to auth_gateway + backend forwarding"""
    url = f"{API_URL}{path}"
    if target:
        url += f"?target={target}"
    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def login_user(username: str, password: str) -> Dict[str, Any]:
    return api_post("/login", {"username": username, "password": password})

def logout_user(username: str, password: str) -> Dict[str, Any]:
    return api_post("/logout", {"username": username, "password": password})

def direct_mcp_call(server_url: str, method: str, params: Optional[Dict[str, Any]] = None, timeout: int = 30) -> Dict[str, Any]:
    """Direct call to MCP server with JSON-RPC payload"""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {}
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream, /"
    }
    
    try:
        response = requests.post(server_url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        # Handle different response formats
        text = response.text.strip()
        
        # Handle SSE-style responses
        if text.startswith("data:") or "data:" in text:
            lines = text.split('\n')
            for line in lines:
                if line.startswith('data:'):
                    data_content = line[5:].strip()
                    try:
                        return json.loads(data_content)
                    except json.JSONDecodeError:
                        return {"result": data_content}
        
        # Handle regular JSON responses
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"result": text}
            
    except requests.exceptions.RequestException as e:
        return {"error": f"MCP server request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def list_tools(server: str) -> list:
    """Fetch available MCP tools for a specific server"""
    session_id = st.session_state.get("session_id")
    if not session_id:
        return []
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "session_id": session_id}
    resp = api_post("/mcp", payload, target=server)
    return resp.get("result", {}).get("tools", [])

def list_mcp_tools(server_url: str):
    """Fetch available MCP tools for a specific server."""
    resp = direct_mcp_call(server_url, "tools/list")
    if not isinstance(resp, dict):
        return []
    
    # Handle different response formats
    result = resp.get("result", {})
    if isinstance(result, dict):
        return result.get("tools", [])
    if isinstance(result, list):
        return result
    
    # Check if tools are at the root level
    if "tools" in resp:
        return resp["tools"]
    
    return []

def call_tool(server: str, tool: str, args: dict) -> Dict[str, Any]:
    """Call an MCP tool through the gateway"""
    session_id = st.session_state.get("session_id")
    if not session_id:
        return {"error": "Not logged in"}
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args, "session_id": session_id},
    }
    return api_post("/mcp", payload, target=server)

def call_tool_direct(server_url: str, name: str, arguments: dict):
    """Execute MCP tool by name with arguments."""
    if not name or not isinstance(arguments, dict):
        return {"error": "Invalid tool name or arguments"}
    
    return direct_mcp_call(server_url, "tools/call", {
        "name": name,
        "arguments": arguments
    })

def sanitize_args(args: dict):
    """Fix arguments before sending to MCP tools."""
    if not args:
        return {}

    fixed = args.copy()
    
    # Handle resource/resourceType naming
    if "resource" in fixed and "resourceType" not in fixed:
        fixed["resourceType"] = fixed.pop("resource")
    
    # Set default namespace for pods if not specified
    if fixed.get("resourceType") == "pods" and "namespace" not in fixed:
        fixed["namespace"] = "default"
    
    # Handle "all namespaces" request
    if fixed.get("namespace") == "all":
        fixed["allNamespaces"] = True
        fixed.pop("namespace", None)
    
    # Handle "all resources" request
    if fixed.get("resourceType") == "all":
        fixed["allResources"] = True
        fixed.pop("resourceType", None)
    
    # Handle common Kubernetes resource types
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

def detect_server_from_query(query: str, available_servers: list) -> Optional[Dict[str, Any]]:
    """Automatically detect which server to use based on query content."""
    query_lower = query.lower()
    
    # Check each server's tools to see which one matches the query
    for server in available_servers:
        try:
            tools = list_mcp_tools(server["url"])
            tool_names = [t.get("name", "").lower() for t in tools if t.get("name")]
            
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

def get_all_cluster_resources(server_url: str):
    """Get all resources in the cluster by querying multiple resource types."""
    resource_types = [
        "pods", "services", "deployments", "configmaps", 
        "secrets", "namespaces", "nodes"
    ]
    
    all_resources = {}
    
    for resource_type in resource_types:
        try:
            response = call_tool_direct(server_url, "kubectl_get", {
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

def _extract_json_from_text(text: str) -> Optional[dict]:
    """Extract JSON object from free text."""
    try:
        # Find the first { and last }
        start = text.find('{')
        end = text.rfind('}') + 1
        if start != -1 and end != -1 and end > start:
            json_str = text[start:end]
            return json.loads(json_str)
    except Exception:
        pass
    return None

# ---------------- GEMINI HELPERS ----------------
def ask_gemini_for_tool(query: str, tools: list) -> Dict[str, Any]:
    """Ask Gemini (or fallback) to map user query to tool+args"""
    if not tools:
        return {"tool": None, "args": {}, "explanation": "No tools available"}

    tool_names = [t.get("name") for t in tools if "name" in t]
    instruction = f"""
User query: "{query}"
Available tools: {json.dumps(tool_names)}

Rules:
- Choose the tool and args that best answer the query.
- If listing resources in Kubernetes, use kubectl_get with appropriate args.
- Respond ONLY in JSON: {{"tool": "<tool>"|null, "args": {{}}|null, "explanation": "short"}}
"""

    if GEMINI_AVAILABLE:
        try:
            model = genai.GenerativeModel(GEMINI_MODEL)
            resp = model.generate_content(instruction)
            parsed = None
            try:
                parsed = json.loads(resp.text.strip())
            except Exception:
                parsed = None
            return parsed or {"tool": None, "args": {}, "explanation": "Gemini gave invalid response"}
        except Exception as e:
            return {"tool": None, "args": {}, "explanation": f"Gemini error: {str(e)}"}

    # Simple fallback
    q = query.lower()
    if "pod" in q:
        return {"tool": "kubectl_get", "args": {"resourceType": "pods", "allNamespaces": True}, "explanation": "User wants pods"}
    if "service" in q:
        return {"tool": "kubectl_get", "args": {"resourceType": "services", "allNamespaces": True}, "explanation": "User wants services"}
    if "job" in q:
        return {"tool": "jenkins_list_jobs", "args": {}, "explanation": "User wants Jenkins jobs"}
    return {"tool": None, "args": {}, "explanation": "No clear mapping found"}

def ask_gemini_for_tool_decision(query: str, server_url: str):
    """Use Gemini to map user query -> MCP tool + arguments."""
    tools = list_mcp_tools(server_url)
    tool_names = [t["name"] for t in tools if "name" in t]

    # Inject context from session state if available
    context_notes = ""
    if st.session_state.last_known_cluster_name:
        context_notes += f"\nUser previously interacted with cluster: {st.session_state.last_known_cluster_name}"
    if st.session_state.last_known_cluster_size:
        context_notes += f"\nLast known cluster size: {st.session_state.last_known_cluster_size} nodes"

    instruction = f"""
You are an AI agent that maps user queries to MCP tools.
User query: "{query}"
{context_notes}

Available tools in this MCP server: {json.dumps(tool_names, indent=2)}

Rules:
- Only choose from the tools above.
- If the query clearly maps to a tool, return tool + args in JSON.
- If the user asks for "all resources" or "everything in cluster", use kubectl_get with appropriate arguments.
- If unsure, set tool=null and args=null.

Respond ONLY in strict JSON:
{{"tool": "<tool_name>" | null, "args": {{}} | null, "explanation": "Short explanation"}}
"""
    if not GEMINI_AVAILABLE:
        # Fallback logic for common queries
        query_lower = query.lower()
        if "all resources" in query_lower or "everything" in query_lower or "all" in query_lower:
            return {
                "tool": "kubectl_get",
                "args": {"resourceType": "all", "allNamespaces": True},
                "explanation": "User wants to see all resources in cluster"
            }
        elif "pods" in query_lower:
            return {
                "tool": "kubectl_get",
                "args": {"resourceType": "pods", "allNamespaces": True},
                "explanation": "User wants to see all pods"
            }
        elif "services" in query_lower or "svc" in query_lower:
            return {
                "tool": "kubectl_get",
                "args": {"resourceType": "services", "allNamespaces": True},
                "explanation": "User wants to see all services"
            }
        elif "secrets" in query_lower:
            return {
                "tool": "kubectl_get",
                "args": {"resourceType": "secrets", "allNamespaces": True},
                "explanation": "User wants to see all secrets"
            }
        elif "nodes" in query_lower:
            return {
                "tool": "kubectl_get",
                "args": {"resourceType": "nodes"},
                "explanation": "User wants to see all nodes"
            }
        else:
            return {"tool": None, "args": None, "explanation": "Gemini not configured; fallback to chat reply."}
    
    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(instruction)
        text = response.text.strip()
        
        # Try to extract JSON from response
        parsed = None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = _extract_json_from_text(text)
        
        if not parsed:
            parsed = {"tool": None, "args": None, "explanation": f"Gemini invalid response: {text}"}
        
        parsed["args"] = sanitize_args(parsed.get("args") or {})
        return parsed
        
    except Exception as e:
        return {"tool": None, "args": None, "explanation": f"Gemini error: {str(e)}"}

def format_answer(query: str, raw: dict) -> str:
    """Convert raw MCP response into friendly text"""
    if "error" in raw:
        return f"⚠️ Error: {raw['error']}"

    result = raw.get("result")
    if isinstance(result, dict):
        if "items" in result:
            items = result["items"]
            return f"Found {len(items)} items:\n" + "\n".join([f"- {i.get('metadata',{}).get('name','unnamed')}" for i in items])
        if "jobs" in result:
            return f"Jenkins Jobs:\n" + "\n".join([f"- {j['name']}" for j in result.get("jobs", [])])
        if "applications" in result:
            return f"ArgoCD Applications:\n" + "\n".join([f"- {a['name']}" for a in result.get("applications", [])])

    return f"Response: {json.dumps(result, indent=2)}"

def ask_gemini_answer(user_input: str, raw_response: dict) -> str:
    """Use Gemini to convert raw MCP response into human-friendly answer."""
    if not GEMINI_AVAILABLE:
        return generate_fallback_answer(user_input, raw_response)

    try:
        context_notes = ""
        if st.session_state.last_known_cluster_name:
            context_notes += f"\nPreviously known cluster: {st.session_state.last_known_cluster_name}"
        if st.session_state.last_known_cluster_size:
            context_notes += f"\nPreviously known size: {st.session_state.last_known_cluster_size} nodes"

        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = (
            f"User asked: {user_input}\n"
            f"Context: {context_notes}\n\n"
            f"Raw system response:\n{json.dumps(raw_response, indent=2)}\n\n"
            "INSTRUCTIONS:\n"
            "- Respond in clear, natural, conversational English.\n"
            "- If it's a list, format with bullet points.\n"
            "- If it's status, explain health and issues clearly.\n"
            "- If error occurred, DO NOT show raw error. Politely explain what went wrong and suggest what user can do.\n"
            "- If cluster name or size was inferred, mention that explicitly.\n"
            "- If cluster size = 1, say: 'This appears to be a minimal/single-node cluster.'\n"
            "- NEVER show JSON, code, or internal errors to user unless asked.\n"
            "- Be helpful, friendly, and precise."
        )
        
        resp = model.generate_content(prompt)
        answer = getattr(resp, "text", str(resp)).strip()

        # Extract and store cluster info for future context
        extract_and_store_cluster_info(user_input, answer)

        return answer

    except Exception as e:
        return generate_fallback_answer(user_input, raw_response)

def generate_fallback_answer(user_input: str, raw_response: dict) -> str:
    """Generate human-friendly answer without Gemini."""
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
                pods = [f"{item.get('metadata', {}).get('name', 'unnamed')} in {item.get('metadata', {}).get('namespace', 'default')} namespace" for item in items]
                if pods:
                    return f"Found {count} pods:\n" + "\n".join([f"• {pod}" for pod in pods])
                else:
                    return "No pods found."
            
            if "secret" in user_input.lower():
                secrets = [f"{item.get('metadata', {}).get('name', 'unnamed')} in {item.get('metadata', {}).get('namespace', 'default')} namespace" for item in items]
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
    """Extract cluster name/size from Gemini answer and store in session."""
    try:
        # Extract cluster name
        if "cluster name" in user_input.lower():
            patterns = [
                r"cluster[^\w]*([\w-]+)",
                r"name[^\w][:\-]?[^\w]([\w-]+)",
                r"\([\w-]+)\",  # bolded name
            ]
            for pattern in patterns:
                match = re.search(pattern, answer, re.IGNORECASE)
                if match:
                    cluster_name = match.group(1).strip()
                    st.session_state.last_known_cluster_name = cluster_name
                    break

        # Extract cluster size
        if "cluster size" in user_input.lower() or "how many nodes" in user_input.lower():
            numbers = re.findall(r'\b\d+\b', answer)
            if numbers:
                st.session_state.last_known_cluster_size = int(numbers[0])
    except Exception:
        pass  # silent fail

# ---------------- STREAMLIT APP ----------------
def main():
    st.set_page_config(page_title="MCP Assistant", page_icon="🤖", layout="wide")
    st.title("🤖 MaSaOps Bot")

    # LOGIN FORM
    if "session_id" not in st.session_state:
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                resp = login_user(username, password)
                if "session_id" in resp:
                    st.session_state.session_id = resp["session_id"]
                    st.session_state.username = resp["username"]
                    st.session_state.access = resp.get("access", [])
                    st.success(f"Logged in as {resp['username']}")
                else:
                    st.error(resp.get("detail", "Login failed"))
        return

    # LOGOUT BUTTON
    st.sidebar.write(f"👤 {st.session_state.username}")
    
    # Sidebar with settings
    with st.sidebar:
        st.header("⚙ Settings")
        
        # Server discovery
        if st.button("Discover Available Servers"):
            with st.spinner("Discovering MCP servers..."):
                st.success(f"Found {len(SERVERS)} servers")
                for server in SERVERS:
                    st.write(f"• {server['name']}: {server['url']}")
        
        st.text_input("Gemini API Key", value=GEMINI_API_KEY, disabled=True, type="password")
        
        if st.button("Clear Chat History"):
            st.session_state.messages = []
            st.rerun()
            
        if st.button("Logout"):
            logout_user(st.session_state.username, "dummy")  # password optional in your gateway
            st.session_state.clear()
            st.rerun()

    # Chat UI
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Show history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Input
    user_input = st.chat_input("Ask something about your infrastructure...")
    if not user_input:
        return

    # Append user msg
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # Pick a server (first accessible for now)
    if not st.session_state.access:
        answer = "You have no servers assigned. Please ask admin to assign you one."
        st.session_state.messages.append({"role": "assistant", "content": answer})
        with st.chat_message("assistant"):
            st.error(answer)
        return

    # Auto-detect which server to use based on query
    with st.spinner("🔍 Finding the right server for your query..."):
        selected_server = detect_server_from_query(user_input, SERVERS)
    
    if not selected_server:
        error_msg = "No MCP servers available. Please check your servers.json file."
        st.session_state.messages.append({"role": "assistant", "content": error_msg})
        with st.chat_message("assistant"):
            st.error(error_msg)
        return
    
    # Show which server we're using
    server_info = f"🤖 Using server: *{selected_server['name']}*"
    st.session_state.messages.append({"role": "assistant", "content": server_info})
    with st.chat_message("assistant"):
        st.markdown(server_info)

    # Use both methods for tool decision making
    tools = list_tools(selected_server["name"])
    decision = ask_gemini_for_tool(user_input, tools)
    
    # Also use the enhanced decision maker
    enhanced_decision = ask_gemini_for_tool_decision(user_input, selected_server["url"])
    
    # Prefer enhanced decision if it found a tool, otherwise use basic decision
    if enhanced_decision.get("tool"):
        decision = enhanced_decision

    explanation = decision.get("explanation", "I'm figuring out how to help you...")
    st.session_state.messages.append({"role": "assistant", "content": f"💡 {explanation}"})
    with st.chat_message("assistant"):
        st.markdown(f"💡 {explanation}")
    
    tool_name = decision.get("tool")
    tool_args = decision.get("args") or {}
    
    # Execute tool if one was selected
    if tool_name:
        with st.chat_message("assistant"):
            st.markdown(f"🔧 Executing **{tool_name}** ...")
        
        # Special handling for "all resources" request
        if (user_input.lower().strip() in ["show me all resources in cluster", "get all resources", "all resources"] or
            ("all" in user_input.lower() and "resource" in user_input.lower())):
            with st.spinner("🔄 Gathering all cluster resources (this may take a moment)..."):
                all_resources = get_all_cluster_resources(selected_server["url"])
                resp = {"result": all_resources}
        else:
            # Call the tool using the gateway method
            with st.spinner("🔄 Processing your request..."):
                resp = call_tool(selected_server["name"], tool_name, tool_args)
        
        # Generate human-readable response using enhanced formatting
        with st.spinner("📝 Formatting response..."):
            final_answer = ask_gemini_answer(user_input, resp)
        
        # Add to chat history
        st.session_state.messages.append({"role": "assistant", "content": final_answer})
        with st.chat_message("assistant"):
            st.markdown(final_answer)
    
    else:
        # No tool selected - provide helpful suggestions
        helpful_response = (
            "I couldn't find a specific tool to answer your question. Here are some things you can try:\n\n"
            "*For Kubernetes:*\n"
            "- \"List all namespaces\"\n"
            "- \"Show running pods\"\n"
            "- \"Get cluster nodes\"\n"
            "- \"Show all services\"\n"
            "- \"List all secrets\"\n"
            "- \"Show all resources in cluster\"\n\n"
            "*For Jenkins:*\n"
            "- \"List all jobs\"\n"
            "- \"Show build status\"\n\n"
            "*For ArgoCD:*\n"
            "- \"List applications\"\n"
            "- \"Show application status\"\n\n"
            "Or try being more specific about what you'd like to see!"
        )
        
        st.session_state.messages.append({"role": "assistant", "content": helpful_response})
        with st.chat_message("assistant"):
            st.markdown(helpful_response)


if __name__ == "__main__":
    main()
