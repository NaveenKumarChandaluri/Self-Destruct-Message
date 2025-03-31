from flask import Flask, request, jsonify, render_template
import uuid
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape

# Encryption imports
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per minute"]
)

# In-memory store for messages. Each message stores encrypted data and a salt.
messages = {}

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
@limiter.limit("10 per minute")
def create_message():
    data = request.get_json()
    message_text = data.get("message")
    password = data.get("password")
    
    if not message_text or not password:
        return jsonify({"error": "Both message and password are required"}), 400

    # Sanitize the message text (password is used only for key derivation)
    message_text = escape(message_text)
    
    # Generate a random salt for this message
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    
    encrypted_message = f.encrypt(message_text.encode())
    
    message_id = str(uuid.uuid4())
    # Store the encrypted message and the salt (encoded as base64)
    messages[message_id] = {
        "encrypted": encrypted_message,
        "salt": base64.b64encode(salt).decode('utf-8')
    }
    
    logger.info(f"Created message with id {message_id}")
    
    link = f"{request.host_url}view/{message_id}"
    return jsonify({"link": link})

@app.route('/view/<message_id>', methods=['GET', 'POST'])
def view_message(message_id):
    if request.method == 'POST':
        password = request.form.get("password")
        if message_id not in messages:
            return render_template('view.html', error="Message not found or already viewed", disableScreenshot=True)
        
        message_data = messages.get(message_id)
        salt = base64.b64decode(message_data["salt"])
        key = derive_key(password, salt)
        f = Fernet(key)
        try:
            decrypted_message = f.decrypt(message_data["encrypted"]).decode()
        except InvalidToken:
            return render_template('view.html', error="Incorrect password!", disableScreenshot=True)
        
        # Log the event and remove the message (self-destruct)
        logger.info(f"Message with id {message_id} viewed and deleted")
        messages.pop(message_id)
        confirmation = "Secret Message displayed. (This message is now self-destructed. Please do not take screenshots!)"
        return render_template('view.html', message=decrypted_message, disableScreenshot=True, confirmation=confirmation)
    
    return render_template('view.html', disableScreenshot=True)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)
