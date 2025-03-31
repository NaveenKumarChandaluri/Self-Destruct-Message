from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# Store messages temporarily
messages = {}

# HTML Template for message viewing
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>View Secret Message</title>
</head>
<body>
    <h2>Enter Password to View Message</h2>
    <form method="POST">
        <input type="password" name="password" placeholder="Enter Password" required>
        <button type="submit">View Message</button>
    </form>
    <p>{{message}}</p>
</body>
</html>
"""

@app.route('/create', methods=['POST'])
def create_message():
    data = request.json
    message_text = data.get("message")
    password = data.get("password")
    
    if not message_text or not password:
        return jsonify({"error": "Message and password are required"}), 400

    message_id = str(uuid.uuid4())
    messages[message_id] = {"message": message_text, "password": password}
    
    return jsonify({"link": f"{request.host_url}view/{message_id}"})

@app.route('/view/<message_id>', methods=['GET', 'POST'])
def view_message(message_id):
    if request.method == "POST":
        password = request.form.get("password")
        message_data = messages.pop(message_id, None)

        if message_data and message_data["password"] == password:
            return render_template_string(HTML_PAGE, message=f"Secret: {message_data['message']}")
        else:
            return render_template_string(HTML_PAGE, message="Invalid password or message expired!")
    
    return render_template_string(HTML_PAGE, message="")

if __name__ == '__main__':
    app.run(debug=True)
