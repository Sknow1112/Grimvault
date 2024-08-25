from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from .config import Config

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    embedding_hash = db.Column(db.String(256))
    salt = db.Column(db.String(32))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    storage_limit = db.Column(db.BigInteger, default=Config.DEFAULT_STORAGE_LIMIT)
    files = db.relationship('File', backref='owner', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_used_storage(self):
        return sum(file.size for file in self.files)

    def update_last_active(self):
        self.last_active = datetime.utcnow()
        db.session.commit()

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))
    content = db.Column(db.LargeBinary)
    size = db.Column(db.BigInteger)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

from . import login_manager

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
