from flask import Blueprint, render_template, request, jsonify, send_file, abort, redirect, url_for, current_app
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.utils import secure_filename
from .models import User, File
from . import db
from .utils import (create_user, verify_user, get_user_files, upload_file,
                    download_file, delete_file, empty_vault, is_admin,
                    get_all_accounts, delete_account, is_rate_limited,
                    is_account_locked, record_login_attempt, update_storage_limit, ban_user,
                    check_password_strength)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import io
import logging

main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)
files = Blueprint('files', __name__)
admin = Blueprint('admin', __name__)

limiter = Limiter(key_func=get_remote_address)

@main.route('/')
def index():
    if current_user.is_authenticated:
        current_user.update_last_active()
        if current_user.is_admin:
            return redirect(url_for('admin.admin_dashboard'))
        return redirect(url_for('files.dashboard'))
    return render_template('index.html')

@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.admin_dashboard'))
        return redirect(url_for('files.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if is_rate_limited(username) or is_account_locked(username):
            return jsonify({"error": "Too many attempts. Please try again later."}), 429

        user = User.query.filter_by(username=username).first()
        if user and verify_user(username, password):
            if user.is_banned:
                return jsonify({"error": "This account has been banned."}), 403
            login_user(user)
            user.update_last_active()
            record_login_attempt(username, True)
            if user.is_admin:
                logging.info(f"Admin user '{username}' logged in successfully.")
                return jsonify({"message": "Login successful", "redirect": url_for('admin.admin_dashboard')}), 200
            logging.info(f"User '{username}' logged in successfully.")
            return jsonify({"message": "Login successful", "redirect": url_for('files.dashboard')}), 200
        else:
            record_login_attempt(username, False)
            logging.warning(f"Failed login attempt for user '{username}'.")
            return jsonify({"error": "Invalid username or password"}), 401

    return render_template('login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        password_strength = check_password_strength(password)
        if password_strength != "strong":
            return jsonify({"error": f"Password is not strong enough. Current strength: {password_strength}"}), 400

        result = create_user(username, password)
        if "successfully" in result:
            logging.info(f"New user '{username}' registered successfully.")
            return jsonify({"message": result, "redirect": url_for('auth.login')}), 201
        else:
            logging.warning(f"Failed registration attempt for username '{username}': {result}")
            return jsonify({"error": result}), 400

    return render_template('register.html')

@auth.route('/logout')
@login_required
def logout():
    logging.info(f"User '{current_user.username}' logged out.")
    logout_user()
    return redirect(url_for('main.index'))

@files.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin.admin_dashboard'))
    current_user.update_last_active()
    user_files = get_user_files(current_user.username)
    used_storage = current_user.get_used_storage()
    return render_template('dashboard.html', files=user_files, used_storage=used_storage, storage_limit=current_user.storage_limit)

@files.route('/upload', methods=['POST'])
@login_required
def upload():
    current_user.update_last_active()
    if current_user.is_admin:
        return jsonify({"error": "Admins cannot upload files"}), 403
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        filename = secure_filename(file.filename)
        try:
            result = upload_file(current_user.username, filename, file.read())
            logging.info(f"User '{current_user.username}' uploaded file '{filename}'.")
            return jsonify({"message": result}), 200
        except Exception as e:
            logging.error(f"Error uploading file for user '{current_user.username}': {str(e)}")
            return jsonify({"error": "An error occurred while uploading the file. Please try again."}), 500

@files.route('/download/<filename>')
@login_required
def download(filename):
    current_user.update_last_active()
    if current_user.is_admin:
        return jsonify({"error": "Admins cannot download files"}), 403
    file_content = download_file(current_user.username, filename)
    if file_content:
        logging.info(f"User '{current_user.username}' downloaded file '{filename}'.")
        return send_file(
            io.BytesIO(file_content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    else:
        logging.warning(f"File '{filename}' not found for user '{current_user.username}'.")
        return jsonify({"error": "File not found"}), 404

@files.route('/delete/<filename>', methods=['DELETE'])
@login_required
def delete(filename):
    current_user.update_last_active()
    if current_user.is_admin:
        return jsonify({"error": "Admins cannot delete files"}), 403
    result = delete_file(current_user.username, filename)
    logging.info(f"User '{current_user.username}' deleted file '{filename}'.")
    return jsonify({"message": result}), 200

@files.route('/empty', methods=['POST'])
@login_required
def empty():
    current_user.update_last_active()
    if current_user.is_admin:
        return jsonify({"error": "Admins cannot empty vault"}), 403
    password = request.form.get('password')
    if verify_user(current_user.username, password):
        result = empty_vault(current_user.username)
        logging.info(f"User '{current_user.username}' emptied their vault.")
        return jsonify({"message": result}), 200
    else:
        logging.warning(f"Failed attempt to empty vault for user '{current_user.username}'.")
        return jsonify({"error": "Invalid password"}), 401

@admin.route('/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    current_user.update_last_active()
    accounts = get_all_accounts()
    return render_template('admindash.html', accounts=accounts)

@admin.route('/update_storage', methods=['POST'])
@login_required
def update_storage():
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    current_user.update_last_active()
    username = request.json.get('username')
    new_limit = request.json.get('new_limit')
    try:
        new_limit = int(float(new_limit) * 1024 * 1024 * 1024)  # Convert GB to bytes
        result = update_storage_limit(username, new_limit)
        logging.info(f"Admin '{current_user.username}' updated storage limit for user '{username}' to {new_limit} bytes.")
        return jsonify({"message": result}), 200
    except ValueError:
        logging.error(f"Invalid storage limit value provided by admin '{current_user.username}' for user '{username}'.")
        return jsonify({"error": "Invalid storage limit value"}), 400

@admin.route('/ban_user', methods=['POST'])
@login_required
def ban_user_route():
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    current_user.update_last_active()
    username = request.json.get('username')
    ban_status = request.json.get('ban_status')
    result = ban_user(username, ban_status)
    action = "banned" if ban_status else "unbanned"
    logging.info(f"Admin '{current_user.username}' {action} user '{username}'.")
    return jsonify({"message": result}), 200

@admin.route('/delete/<username>', methods=['DELETE'])
@login_required
def admin_delete_account(username):
    if not current_user.is_admin:
        return jsonify({"error": "Access denied"}), 403
    current_user.update_last_active()
    result = delete_account(username)
    logging.info(f"Admin '{current_user.username}' deleted account for user '{username}'.")
    return jsonify({"message": result}), 200
