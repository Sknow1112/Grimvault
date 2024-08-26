import os
import secrets
import hashlib
import time
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from transformers import AutoTokenizer, AutoModel
import torch
import numpy as np
from .models import User, File
from . import db
from huggingface_hub import hf_hub_download
import requests
from dotenv import load_dotenv
import re

load_dotenv()

# Initialize global variables
MODEL_NAME = os.getenv('SECRET_M')
HF_TOKEN = os.getenv('HF_TOKEN')

tokenizer = None
model = None

# Initialize Argon2 hasher and Fernet cipher
ph = PasswordHasher()
cipher_key = Fernet.generate_key()
cipher = Fernet(cipher_key)

def get_embedding(text):
    global tokenizer, model

    if tokenizer is None or model is None:
        try:
            tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, use_auth_token=HF_TOKEN)
            model = AutoModel.from_pretrained(MODEL_NAME, torch_dtype=torch.float16, use_auth_token=HF_TOKEN)

            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token

            model.resize_token_embeddings(len(tokenizer))
        except (requests.exceptions.RequestException, OSError) as e:
            print(f"Error loading model: {str(e)}")
            return None

    inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
    return outputs.last_hidden_state.mean(dim=1).squeeze().numpy()

def hash_embedding(embedding, salt):
    salted_embedding = np.concatenate([embedding, np.frombuffer(salt, dtype=np.float32)])
    return hashlib.sha256(salted_embedding.tobytes()).hexdigest()

def create_user(username, password):
    if User.query.filter_by(username=username).first():
        return "Username already exists."

    salt = secrets.token_bytes(16)
    embedding = get_embedding(password)
    if embedding is None:
        return "Error creating user. Please try again later."
    embedding_hash = hash_embedding(embedding, salt)

    new_user = User(username=username, salt=salt.hex(), embedding_hash=embedding_hash)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    return "User created successfully."

def verify_user(username, password):
    user = User.query.filter_by(username=username).first()
    if not user:
        return False

    if not user.check_password(password):
        return False

    embedding = get_embedding(password)
    if embedding is None:
        return False
    embedding_hash = hash_embedding(embedding, bytes.fromhex(user.salt))
    return embedding_hash == user.embedding_hash

def get_user_files(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return []
    return [{"filename": file.filename, "size": file.size} for file in user.files]

def upload_file(username, filename, content):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found."

    if user.get_used_storage() + len(content) > user.storage_limit:
        return "Storage limit exceeded."

    existing_file = File.query.filter_by(user_id=user.id, filename=filename).first()
    if existing_file:
        return f"File {filename} already exists."

    encrypted_content = cipher.encrypt(content)
    new_file = File(filename=filename, content=encrypted_content, size=len(content), user_id=user.id)
    db.session.add(new_file)
    db.session.commit()

    return f"File {filename} uploaded successfully."

def download_file(username, filename):
    user = User.query.filter_by(username=username).first()
    if not user:
        return None

    file = File.query.filter_by(user_id=user.id, filename=filename).first()
    if not file:
        return None

    return cipher.decrypt(file.content)

def delete_file(username, filename):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found."

    file = File.query.filter_by(user_id=user.id, filename=filename).first()
    if not file:
        return f"File {filename} not found."

    db.session.delete(file)
    db.session.commit()
    return f"File {filename} deleted successfully."

def empty_vault(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found."

    File.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return "All files in your vault have been deleted."

def is_admin(username):
    user = User.query.filter_by(username=username).first()
    return user and user.is_admin

def get_all_accounts():
    return [{"username": user.username, "created_at": user.created_at, "last_active": user.last_active, "storage_used": user.get_used_storage(), "storage_limit": user.storage_limit, "is_banned": user.is_banned} for user in User.query.all()]

def delete_account(username):
    if username == os.getenv('ADMIN_USERNAME'):
        return "Cannot delete admin account."

    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found."

    File.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    return f"Account {username} and all associated files have been deleted."

def update_storage_limit(username, new_limit):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found."

    user.storage_limit = new_limit
    db.session.commit()
    return f"Storage limit for {username} updated to {new_limit / (1024 * 1024 * 1024):.2f} GB."

def ban_user(username, ban_status):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found."

    user.is_banned = ban_status
    db.session.commit()
    action = "banned" if ban_status else "unbanned"
    return f"User {username} has been {action}."

# Rate limiting
RATE_LIMIT = 5  # maximum number of requests per minute
rate_limit_dict = {}

def is_rate_limited(username):
    current_time = time.time()
    if username in rate_limit_dict:
        last_request_time, count = rate_limit_dict[username]
        if current_time - last_request_time < 60:  # within 1 minute
            if count >= RATE_LIMIT:
                return True
            rate_limit_dict[username] = (last_request_time, count + 1)
        else:
            rate_limit_dict[username] = (current_time, 1)
    else:
        rate_limit_dict[username] = (current_time, 1)
    return False

# Account lockout
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes
lockout_dict = {}

def is_account_locked(username):
    if username in lockout_dict:
        attempts, lockout_time = lockout_dict[username]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            if time.time() - lockout_time < LOCKOUT_TIME:
                return True
            else:
                del lockout_dict[username]
    return False

def record_login_attempt(username, success):
    if username not in lockout_dict:
        lockout_dict[username] = [0, 0]

    if success:
        del lockout_dict[username]
    else:
        lockout_dict[username][0] += 1
        lockout_dict[username][1] = time.time()

def check_password_strength(password):
    # Check password length
    if len(password) < 8:
        return "weak"

    # Check for uppercase, lowercase, digit, and special character
    if not re.search(r'[A-Z]', password):
        return "medium"
    if not re.search(r'[a-z]', password):
        return "medium"
    if not re.search(r'\d', password):
        return "medium"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "medium"

    return "strong"
