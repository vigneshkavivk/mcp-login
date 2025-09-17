import os
from pymongo import MongoClient
from passlib.hash import bcrypt
from dotenv import load_dotenv
import urllib.parse

load_dotenv()

# Get raw URI
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

# Parse and reconstruct URI with escaped username/password
from urllib.parse import urlparse, urlunparse

parsed = urlparse(MONGO_URI)

# If there's a username/password, escape them
if parsed.username or parsed.password:
    username = urllib.parse.quote_plus(parsed.username) if parsed.username else ""
    password = urllib.parse.quote_plus(parsed.password) if parsed.password else ""
    netloc = f"{username}:{password}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    # Rebuild URI
    MONGO_URI = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

# Now connect
client = MongoClient(MONGO_URI)
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
