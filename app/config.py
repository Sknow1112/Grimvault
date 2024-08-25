import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, '..', 'grimvault.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload settings
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024 * 1024  # 5 GB
    UPLOAD_FOLDER = os.path.join(basedir, '..', 'uploads')
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    
    # Custom settings
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    HF_TOKEN = os.environ.get('HF_TOKEN')
    SECRET_M = os.environ.get('SECRET_M')
    
    # Rate limiting
    RATELIMIT_DEFAULT = "5 per minute"
    RATELIMIT_STORAGE_URL = "memory://"

    # Default storage limit (5 GB in bytes)
    DEFAULT_STORAGE_LIMIT = 5 * 1024 * 1024 * 1024