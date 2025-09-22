from werkzeug.security import generate_password_hash
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

def create_db_and_user(email="test@example.com", password="testpassword"):
    with app.app_context():
        db.create_all()
        if User.query.filter_by(email=email).first():
            print(f"User {email} already exists in users.db")
            return
        hashed = generate_password_hash(password)
        user = User(email=email, password=hashed)
        db.session.add(user)
        db.session.commit()
        print(f"Created users.db and added user: {email} with password: {password}")

if __name__ == "__main__":
    # change email/password here if you want
    create_db_and_user(email="shahida7135@gmail.com", password="MyTestPass123")
