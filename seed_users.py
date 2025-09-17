import os
from pymongo import MongoClient
from passlib.hash import bcrypt
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

# Get raw URI
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

# Escape username and password if they exist
from urllib.parse import urlparse, urlunparse

parsed = urlparse(MONGO_URI)
username = quote_plus(parsed.username) if parsed.username else ""
password = quote_plus(parsed.password) if parsed.password else ""
host = parsed.hostname
port = f":{parsed.port}" if parsed.port else ""
netloc = f"{username}:{password}@{host}{port}" if username and password else f"{host}{port}"

# Rebuild full URI including query
MONGO_URI_ESCAPED = urlunparse((
    parsed.scheme,
    netloc,
    parsed.path or "",
    parsed.params or "",
    parsed.query or "",
    parsed.fragment or ""
))

# Connect
client = MongoClient(MONGO_URI_ESCAPED)
db = client[DB_NAME]
users = db.users

# Drop existing for clean start
users.drop()

user_data = [
    {"username": "vicky", "password": bcrypt.hash("vicky123"), "access": ["kubernetes", "jenkins", "argocd"]},
    {"username": "abi", "password": bcrypt.hash("abi123"), "access": ["kubernetes", "argocd"]},
    {"username": "saro", "password": bcrypt.hash("saro123"), "access": ["jenkins"]}
]

users.insert_many(user_data)
print("Users seeded successfully.")
