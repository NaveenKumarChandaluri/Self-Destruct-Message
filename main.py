from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# In-memory store for messages
messages = {}

# Root route to avoid 404 errors on "/"
@app.route('/')
def home():
    return "Hello, Flask is running! This is the Self-Destruct Message App."

# Create message endpoint (expects JSON POST with keys "message" and "password")
@app.route('/create', methods=['POST'])
def create_message():
    data = request.json
    message_text = data.get("message")
    password = data.get("password")
    
    if not message_text or not password:
        return jsonify({"error": "Both message and password are required"}), 400

    message_id = str(uuid.uuid4())
    messages[message_id] = {"message": message_text, "password": password}
    
    # Construct the public link using the host URL
    link = f"{request.host_url}view/{message_id}"
    return jsonify({"link": link})

# View message endpoint:
# GET: Displays a form to enter the password.
# POST: Processes the form, validates the password, and returns the message.
@app.route('/view/<message_id>', methods=['GET', 'POST'])
def view_message(message_id):
    if request.method == 'POST':
        password = request.form.get("password")
        if message_id not in messages:
            return render_template_string("<h3>Message not found or already viewed!</h3>")
        message_data = messages.pop(message_id)
        if message_data["password"] != password:
            return render_template_string("<h3>Incorrect password!</h3>")
        return render_template_string("<h3>Secret Message: {{ msg }}</h3>", msg=message_data["message"])
    
    # GET: Show the password form
    return render_template_string("""
        <h2>Enter Password to View the Message</h2>
        <form method="post">
            <input type="password" name="password" placeholder="Enter Password" required>
            <button type="submit">View Message</button>
        </form>
    """)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)
