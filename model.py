from __main__ import app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import enum

from itsdangerous import URLSafeTimedSerializer

db = SQLAlchemy(app)

class YourRole(enum.Enum):
    admin = "admin"
    user = "user"  
class User(db.Model):
    __tablename__='user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role=db.Column(db.Enum(YourRole))

    users_info = db.relationship('Task', backref='users')
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
class Task(db.Model):
    __tablename__='tasks'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    task = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)
    
    task_info = db.relationship('Comments', backref='tasks')
    def assign(self):
        db.session.add(self)
        db.session.commit()
    def remove(self):
        db.session.delete(self)
        db.session.commit()
class Comments(db.Model):
    __tablename__='comments'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    comment = db.Column(db.String(100))
    tasks_id = db.Column(db.Integer, db.ForeignKey('tasks.id'),nullable=False)

    def add(self):
        db.session.add(self)
        db.session.commit()
    def remove(self):
        db.session.delete(self)
        db.session.commit()
with app.app_context():
    db.create_all()