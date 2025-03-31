from flask import Flask, request, jsonify, render_template
import uuid

app = Flask(__name__)

messages = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
def create_message():
    data = request.json
    message_text = data.get("message")
    password = data.get("password")
    
    if not message_text or not password:
        return jsonify({"error": "Both message and password are required"}), 400

    message_id = str(uuid.uuid4())
    messages[message_id] = {"message": message_text, "password": password}
    
    # Use request.host_url so the link is dynamic
    return jsonify({"link": f"{request.host_url}view/{message_id}"})

@app.route('/view/<message_id>', methods=['GET', 'POST'])
def view_message(message_id):
    if request.method == 'POST':
        password = request.form.get("password")
        if message_id not in messages:
            return "Message not found or already viewed!"
        message_data = messages.pop(message_id)
        if message_data["password"] != password:
            return "Incorrect password!"
        return f"Secret Message: {message_data['message']}"
    
    # GET: Display a simple password form
    return '''
        <h2>Enter Password to View the Message</h2>
        <form method="post">
            <input type="password" name="password" placeholder="Enter Password" required>
            <button type="submit">View Message</button>
        </form>
    '''

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)
