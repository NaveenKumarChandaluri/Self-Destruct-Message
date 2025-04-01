from flask import Flask, request, jsonify, render_template, send_file, url_for, redirect
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

# In-memory store for messages
messages = {}

# Maximum time (in seconds) that a message remains accessible (1 minute)
MAX_VIEW_DURATION = 60

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

    message_text = escape(message_text)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message_text.encode())

    msg_record = {
        "encrypted": encrypted_message,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "created_at": time.time()
        # We'll add "viewed", "decrypted" and "password" keys later after the correct password is submitted.
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
    if message_id not in messages:
        return render_template('view.html', error="Message not found or already viewed", disableScreenshot=True)
    message_data = messages.get(message_id)
    # Expire if too old
    if current_time - message_data.get('created_at') > MAX_VIEW_DURATION:
        messages.pop(message_id, None)
        return render_template('view.html', error="Message expired", disableScreenshot=True)

    # Handle POST: user submits password
    if request.method == 'POST':
        password = request.form.get("password")
        salt = base64.b64decode(message_data["salt"])
        key = derive_key(password, salt)
        f = Fernet(key)
        try:
            decrypted_message = f.decrypt(message_data["encrypted"]).decode()
        except InvalidToken:
            return render_template('view.html', error="Incorrect password!", disableScreenshot=True)
        # Mark as viewed and store decrypted message and password for download link
        message_data['viewed'] = current_time
        message_data['decrypted'] = decrypted_message
        message_data['password'] = password
        # Redirect to display route with a flag indicating a fresh display
        return redirect(url_for('display_message', message_id=message_id, fresh=1))
    
    # For a GET request on /view/<message_id> (i.e. initial load before password submission)
    # Show the password form.
    return render_template('view.html', disableScreenshot=True)

@app.route('/display/<message_id>', methods=['GET'])
def display_message(message_id):
    current_time = time.time()
    if message_id not in messages:
        return render_template('view.html', error="Message not found or already viewed", disableScreenshot=True)
    message_data = messages.get(message_id)
    # Expire if too old
    if current_time - message_data.get('created_at') > MAX_VIEW_DURATION:
        messages.pop(message_id, None)
        return render_template('view.html', error="Message expired", disableScreenshot=True)
    # If the 'fresh' query parameter is present, this is the first display after password submission.
    # Otherwise, if user refreshes the page (i.e. URL without fresh=1), then expire the message.
    if request.args.get('fresh') != '1':
        messages.pop(message_id, None)
        return render_template('view.html', error="Message expired", disableScreenshot=True)
    
    remaining_time = MAX_VIEW_DURATION - (current_time - message_data.get('created_at'))
    # Render the page showing the decrypted message and download link.
    # The download link will be generated using the stored password.
    return render_template(
        'view.html',
        message=message_data.get('decrypted'),
        attachment=message_data.get("attachment"),
        disableScreenshot=True,
        message_id=message_id,
        password=message_data.get('password'),
        remaining_time=int(remaining_time)
    )

@app.route('/download/<message_id>', methods=['GET'])
def download_attachment(message_id):
    current_time = time.time()
    password = request.args.get("password")
    if not password:
        return "Password required", 400
    if message_id not in messages:
        return "Message not found or expired", 404
    message_data = messages.get(message_id)
    if current_time - message_data.get('created_at') > MAX_VIEW_DURATION:
        messages.pop(message_id, None)
        return "Message expired", 404
    # Only allow download if the message has been viewed (i.e. 'viewed' key exists)
    if 'viewed' not in message_data:
        return "Message not viewed yet", 403
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
    # After a successful download, remove the message so further access fails.
    messages.pop(message_id, None)
    return send_file(io.BytesIO(decrypted_file_data), download_name=attachment["filename"], as_attachment=True)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)
