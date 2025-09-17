import os
from pymongo import MongoClient
from passlib.hash import bcrypt
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

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
