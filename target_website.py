"""
target_website.py — E-Commerce Target App with Detailed SIEM Logging.
"""

from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)
SIEM_URL = "http://127.0.0.1:5000/api/ingest"


def send_to_siem(event_type, user="Guest", status_code=200, extra_msg=""):
    path_with_query = request.path
    if request.query_string:
        path_with_query += f"?{request.query_string.decode()}"
        
    full_message = f"[{request.method}] {path_with_query}"
    if extra_msg:
        full_message += f" ({extra_msg})"
    
    payload = {
        "source": "Web Application (Port 8000)",
        "host": "127.0.0.1",
        "user": user,
        "event_id": status_code,
        "message": full_message,
        "process_name": "target_website.py"
    }
    
    try:
        requests.post(SIEM_URL, json=payload, timeout=2)
    except Exception as e:
        print(f"[WARN] SIEM not reachable: {e}")


@app.before_request
def log_request_middleware():
    if "favicon.ico" not in request.path:
        send_to_siem("HTTP Request", extra_msg="Page Visited")


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Target Web Application — SIEM Testbed</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f2f5; margin: 40px; }
        .card { background: white; padding: 25px; border-radius: 8px; max-width: 550px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px;}
        input { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; }
        button { background: #0066cc; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .attack-box { border-left: 4px solid #e53e3e; background: #fff5f5; }
    </style>
</head>
<body>
    <h2>🛍️ E-Commerce Portal Target App</h2>
    
    <div class="card">
        <h3>User Login</h3>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="user@example.com" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>

    <div class="card attack-box">
        <h3>⚡ Attack Simulation Suite</h3>
        <p>Click these actions to send attacks to Raptor Guard SIEM:</p><br>
        <a href="/search?q=' OR '1'='1"><button style="background: #e53e3e;">Trigger SQL Injection (Level 13)</button></a><br><br>
        <a href="/search?q=<script>alert('XSS')</script>"><button style="background: #e53e3e;">Trigger XSS Attack (Level 10)</button></a><br><br>
        <a href="/download?file=../../../../etc/passwd"><button style="background: #e53e3e;">Trigger Path Traversal (Level 10)</button></a><br><br>
        <a href="/admin"><button style="background: #dd6b20;">Scan /admin Directory (Level 6)</button></a>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    if username == "admin@example.com" and password == "Secret123!":
        send_to_siem("Login Success", user=username, status_code=200)
        return "<h3>Login Successful!</h3><a href='/'>Back</a>"
    else:
        send_to_siem("Login Failed", user=username, status_code=401, extra_msg=f"Failed auth for user: {username}")
        return "<h3>Invalid Credentials!</h3><a href='/'>Try Again</a>", 401

@app.route('/search')
def search():
    return f"<h3>Search Query: {request.args.get('q', '')}</h3><a href='/'>Back</a>"

@app.route('/download')
def download():
    return f"<h3>File: {request.args.get('file', '')}</h3><a href='/'>Back</a>"

@app.route('/admin')
def admin():
    send_to_siem("Admin Scan", status_code=403, extra_msg="Unauthorized access to /admin")
    return "<h3>403 Forbidden</h3><a href='/'>Back</a>", 403

if __name__ == '__main__':
    print("Target Web App running on http://127.0.0.1:8000 ...")
    app.run(host='127.0.0.1', port=8000)