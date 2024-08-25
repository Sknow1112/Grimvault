from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from .config import Config
import os
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
login_manager = LoginManager()
scheduler = BackgroundScheduler()

def create_app():
    app = Flask(__name__,
                template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'templates'),
                static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static'))
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    from .routes import main, auth, files, admin
    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(files)
    app.register_blueprint(admin, url_prefix='/admin')

    with app.app_context():
        db.create_all()
        create_admin_user()

    scheduler.add_job(delete_inactive_users, 'interval', hours=1)
    scheduler.start()

    return app

def create_admin_user():
    from .models import User
    from .utils import create_user

    admin_username = os.getenv('ADMIN_USERNAME')
    admin_password = os.getenv('ADMIN_PASSWORD')

    if admin_username and admin_password:
        existing_admin = User.query.filter_by(username=admin_username).first()
        if not existing_admin:
            result = create_user(admin_username, admin_password)
            if "successfully" in result:
                admin_user = User.query.filter_by(username=admin_username).first()
                admin_user.is_admin = True
                admin_user.storage_limit = 1024 * 1024 * 1024 * 10  # 10 GB for admin
                db.session.commit()
                print(f"Admin user '{admin_username}' created successfully.")
            else:
                print(f"Failed to create admin user: {result}")
        else:
            print(f"Admin user '{admin_username}' already exists.")
    else:
        print("Admin credentials not provided in environment variables.")

def delete_inactive_users():
    from .models import User
    from datetime import datetime, timedelta
    with db.app.app_context():
        inactive_threshold = datetime.utcnow() - timedelta(hours=42)
        inactive_users = User.query.filter(User.last_active < inactive_threshold).all()
        for user in inactive_users:
            db.session.delete(user)
        db.session.commit()
