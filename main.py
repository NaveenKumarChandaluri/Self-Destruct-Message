from flask import Flask, request, jsonify, render_template, send_file
import uuid
import logging
import time
import os
import base64
import io

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape

# Encryption imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Setup rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per minute"]
)

# In-memory store for messages.
# Each message record is a dict that includes:
# - "encrypted": encrypted text message (bytes)
# - "salt": salt used for key derivation (base64-encoded string)
# - optionally, "attachment": { "filename": ..., "data": encrypted file (base64-encoded string) }
# - if viewed, "viewed": timestamp (float)
messages = {}

# Maximum time (in seconds) that a viewed message remains accessible (10 minutes)
MAX_VIEW_DURATION = 600

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
@limiter.limit("10 per minute")
def create_message():
    # Support both multipart/form-data (for file uploads) and JSON.
    if request.content_type.startswith("multipart/form-data"):
        message_text = request.form.get("message")
        password = request.form.get("password")
        file = request.files.get("attachment")
    else:
        data = request.get_json()
        message_text = data.get("message")
        password = data.get("password")
        file = None

    if not message_text or not password:
        return jsonify({"error": "Both message and password are required"}), 400

    # Sanitize the message text (password is used for key derivation only)
    message_text = escape(message_text)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message_text.encode())

    msg_record = {
        "encrypted": encrypted_message,
        "salt": base64.b64encode(salt).decode('utf-8')
    }

    if file:
        file_bytes = file.read()
        encrypted_file = f.encrypt(file_bytes)
        msg_record["attachment"] = {
            "filename": file.filename,
            "data": base64.b64encode(encrypted_file).decode('utf-8')
        }

    message_id = str(uuid.uuid4())
    messages[message_id] = msg_record
    logger.info(f"Created message with id {message_id}")
    link = f"{request.host_url}view/{message_id}"
    return jsonify({"link": link})

@app.route('/view/<message_id>', methods=['GET', 'POST'])
def view_message(message_id):
    current_time = time.time()
    if request.method == 'POST':
        password = request.form.get("password")
        if message_id not in messages:
            return render_template('view.html', error="Message not found or already viewed", disableScreenshot=True)
        message_data = messages.get(message_id)
        # If message was viewed and expired, remove it.
        if 'viewed' in message_data and current_time - message_data['viewed'] > MAX_VIEW_DURATION:
            messages.pop(message_id, None)
            return render_template('view.html', error="Message expired", disableScreenshot=True)
        salt = base64.b64decode(message_data["salt"])
        key = derive_key(password, salt)
        f = Fernet(key)
        try:
            decrypted_message = f.decrypt(message_data["encrypted"]).decode()
        except InvalidToken:
            return render_template('view.html', error="Incorrect password!", disableScreenshot=True)
        # Mark as viewed if not already set.
        if 'viewed' not in message_data:
            message_data['viewed'] = current_time
        confirmation = "Secret Message displayed. This message will expire in 10 minutes. Please do not take screenshots."
        return render_template('view.html', message=decrypted_message, attachment=message_data.get("attachment"), disableScreenshot=True, confirmation=confirmation, message_id=message_id, password=password)
    return render_template('view.html', disableScreenshot=True)

@app.route('/download/<message_id>', methods=['GET'])
def download_attachment(message_id):
    current_time = time.time()
    password = request.args.get("password")
    if not password:
        return "Password required", 400
    if message_id not in messages:
        return "Message not found or expired", 404
    message_data = messages.get(message_id)
    if 'viewed' not in message_data or current_time - message_data['viewed'] > MAX_VIEW_DURATION:
        messages.pop(message_id, None)
        return "Message expired", 404
    salt = base64.b64decode(message_data["salt"])
    key = derive_key(password, salt)
    f = Fernet(key)
    attachment = message_data.get("attachment")
    if not attachment:
        return "No attachment", 404
    try:
        encrypted_data = base64.b64decode(attachment["data"])
        decrypted_file_data = f.decrypt(encrypted_data)
    except InvalidToken:
        return "Incorrect password", 403
    return send_file(io.BytesIO(decrypted_file_data), download_name=attachment["filename"], as_attachment=True)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)
