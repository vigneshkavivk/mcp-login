import streamlit as st
import requests

API_URL = "http://localhost:8080"

st.title("MCP Bot Client")

if "session" not in st.session_state:
    st.session_state.session = None
    st.session_state.access = []

if not st.session_state.session:
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        resp = requests.post(f"{API_URL}/login", json={"username": username, "password": password})
        if resp.status_code == 200:
            data = resp.json()
            st.session_state.session = data["session_id"]
            st.session_state.access = data["access"]
            st.success(f"Logged in! Access: {', '.join(st.session_state.access)}")
        else:
            st.error(resp.json().get("detail"))
else:
    st.subheader("Available Backends")
    backend = st.selectbox("Select Backend", st.session_state.access)
    action = st.text_input("Action to send")
    if st.button("Send"):
        resp = requests.post(f"{API_URL}/mcp/{backend}/{action}", json={"data": "test"})
        st.json(resp.json())
