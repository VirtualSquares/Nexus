from flask import Flask, render_template, request, redirect, url_for, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "[YOUR_APP_SECRET_KEY]"

client = MongoClient("YOUR_MONGO_CLIENT")
db = client.Evaluation

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("index.html", error=None)

    username = request.form["username"]
    password = request.form["password"]
    existing_user = db.credentials.find_one({"username": username})

    if existing_user:
        error_message = "Username already taken, please choose another one."
        return render_template("index.html", error=error_message)

    hashed_password = generate_password_hash(password)
    db.credentials.insert_one({"username": username, "password": hashed_password})
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form["username"]
    password = request.form["password"]
    user = db.credentials.find_one({"username": username})
    if user and check_password_hash(user["password"], password):
        session['username'] = username
        return redirect(url_for("dashboard"))
    return "Invalid username or password"

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    username = request.form["username"]
    new_password = request.form["new-password"]
    user = db.credentials.find_one({"username": username})
    if user:
        hashed_password = generate_password_hash(new_password)
        db.credentials.update_one({"username": username}, {"$set": {"password": hashed_password}})
        return redirect(url_for("login"))
    return "Username not found, please try again."

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    current_user = session['username']
    users = db.credentials.find({"username": {"$ne": current_user}})
    messages = []
    if request.method == "POST":
        recipient = request.form["recipient"]
        message = request.form["message"]
        if recipient and message:
            message_data = {
                "sender": current_user,
                "receiver": recipient,
                "message": message,
                "timestamp": datetime.now()
            }
            db.messages.insert_one(message_data)
            return redirect(url_for("dashboard", recipient=recipient))
    recipient = request.args.get('recipient')
    if recipient:
        messages = db.messages.find({
            "$or": [
                {"sender": current_user, "receiver": recipient},
                {"sender": recipient, "receiver": current_user}
            ]
        }).sort("timestamp")
    return render_template("dashboard.html", users=users, messages=messages, current_user=current_user)

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)
