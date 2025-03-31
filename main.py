from flask import Flask, request, jsonify, render_template, redirect, url_for
import uuid
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape

app = Flask(__name__)

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Setup rate limiting: 60 requests per minute globally, 10 per minute on /create
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["60 per minute"]
)

# In-memory store for messages
messages = {}

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

    # Sanitize inputs
    message_text = escape(message_text)
    password = escape(password)
    
    message_id = str(uuid.uuid4())
    messages[message_id] = {"message": message_text, "password": password}
    
    logger.info(f"Created message with id {message_id}")
    
    # Return a dynamic link
    link = f"{request.host_url}view/{message_id}"
    return jsonify({"link": link})

@app.route('/view/<message_id>', methods=['GET', 'POST'])
def view_message(message_id):
    if request.method == 'POST':
        password = request.form.get("password")
        if message_id not in messages:
            return render_template('view.html', error="Message not found or already viewed", disableScreenshot=True)
        message_data = messages.get(message_id)
        if message_data["password"] != password:
            return render_template('view.html', error="Incorrect password!", disableScreenshot=True)
        
        # Log the view event and remove the message (self-destruct)
        logger.info(f"Message with id {message_id} viewed and deleted")
        message_content = messages.pop(message_id)["message"]
        confirmation = "Secret Message displayed. (This message is now self-destructed. Please do not take screenshots!)"
        return render_template('view.html', message=message_content, disableScreenshot=True, confirmation=confirmation)
    
    # GET: Display the password form for viewing the message
    return render_template('view.html', disableScreenshot=True)

# Custom error handler for 404 errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Custom error handler for 500 errors
@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Render uses port binding automatically; here we bind to port 10000
    app.run(host="0.0.0.0", port=10000, debug=True)
