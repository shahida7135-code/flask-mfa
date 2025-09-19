import os
import secrets
import smtplib
import pickle
from email.message import EmailMessage
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(16))

# Database setup (SQLite)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# OTP generator
def generate_numeric_otp(length=6):
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])

# Send OTP email
def send_otp_email(receiver_email, otp):
    msg = EmailMessage()
    msg["Subject"] = "Your OTP for Login"
    msg["From"] = os.getenv("MAIL_USERNAME")
    msg["To"] = receiver_email
    msg.set_content(f"Your OTP is: {otp}. It is valid for 5 minutes.")

    with smtplib.SMTP(os.getenv("MAIL_SERVER"), int(os.getenv("MAIL_PORT"))) as server:
        server.starttls()
        server.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
        server.send_message(msg)

# Send alert email if malicious query detected
def send_alert_email(query):
    admin_email = os.getenv("ADMIN_EMAIL")
    msg = EmailMessage()
    msg["Subject"] = "⚠️ Malicious SQL Query Detected"
    msg["From"] = os.getenv("MAIL_USERNAME")
    msg["To"] = admin_email
    msg.set_content(f"A malicious query was detected:\n\n{query}")

    with smtplib.SMTP(os.getenv("MAIL_SERVER"), int(os.getenv("MAIL_PORT"))) as server:
        server.starttls()
        server.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
        server.send_message(msg)

# Load ML Pipeline
with open("pipeline.pkl", "rb") as f:
    pipeline = pickle.load(f)

# Check SQL query and send alert if malicious
def check_query(query):
    result = pipeline.predict([query])[0]  # Safe or Malicious
    if result == "Malicious":
        send_alert_email(query)
    return result

# Routes
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            otp = generate_numeric_otp(6)
            session["otp"] = otp
            session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
            session["email"] = email
            send_otp_email(email, otp)
            flash("OTP sent to your email.", "info")
            return redirect(url_for("otp"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route("/otp", methods=["GET", "POST"])
def otp():
    if request.method == "POST":
        entered_otp = request.form["otp"]
        otp = session.get("otp")
        expiry = session.get("otp_expiry")

        if otp and expiry and datetime.utcnow() < datetime.fromisoformat(expiry):
            if entered_otp == otp:
                session["logged_in"] = True
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid OTP!", "danger")
        else:
            flash("OTP expired. Please login again.", "danger")
            return redirect(url_for("login"))

    return render_template("otp.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if not session.get("logged_in"):
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    prediction = None
    if request.method == "POST":
        sql_query = request.form["sql_query"]

        # ← Place it here
        prediction = pipeline.predict([sql_query])[0]  # Safe or Malicious
        if prediction == "Malicious":
            send_alert_email(sql_query)
            flash("Malicious query detected! Admin alerted.", "danger")
        else:
            flash("Query is safe.", "success")

    return render_template("dashboard.html", prediction=prediction)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
