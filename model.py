from __main__ import app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy(app)
tk=SQLAlchemy(app)
class User(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role=db.Column(db.String(100))
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def save(self):
        db.session.add(self)
        db.session.commit()
    def remove(self):
        db.session.delete(self)
        db.session.commit()
with app.app_context():
    db.create_all()
class Task(tk.Model):
    id = tk.Column(tk.Integer, primary_key=True)
    username = tk.Column(tk.String(50), unique=True, nullable=False)
    role=tk.Column(tk.String(100))
    task = tk.Column(tk.String(100))
    def assign(self):
        tk.session.add(self)
        tk.session.commit()
    def remove(self):
        tk.session.delete(self)
        tk.session.commit()
class Comments(tk.Model):
    id = tk.Column(tk.Integer, primary_key=True)
    username = tk.Column(tk.String(50), unique=True, nullable=False)
    comment = tk.Column(tk.String(100))
    def add(self):
        tk.session.add(self)
        tk.session.commit()
    def remove(self):
        tk.session.delete(self)
        tk.session.commit()
with app.app_context():
    tk.create_all()