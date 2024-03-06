from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token
from flask_jwt_extended import create_access_token
import os
from flask_mail import Mail, Message
from functools import wraps
from flask import g, request, redirect, url_for
from dotenv import load_dotenv


load_dotenv()
app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
jwt = JWTManager(app)
mail = Mail(app)
from model import User,Task, Comments,YourRole
from decorators import is_admin

@app.route('/register', methods=['GET','POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role=data['role']
    email=data['email']
    user = User(username=username,role=role)
    user.set_password(password)
    existing_user= User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message':'User already exist'}),201
    elif role!="admin" and role!="user":
        return jsonify({'message':'not a valid role'}),401
    else:
        msg = Message(subject='Registration Successful', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = "Hey, "+username+" you are successfully registered for the role of "+role
        mail.send(msg)
        user.save()
        return jsonify({'message': 'User registered successfully'}),201

@app.route('/login', methods=['GET','POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity='user_id')
        user.remove()
        return jsonify({'message': 'Login successful'}),201
    else:
        return jsonify({'message': 'Invalid username or password'}),401


@app.route('/delete', methods=['GET','POST'])
def delete():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        user.remove()
        return jsonify({'message': 'user data deleted successfully'}),201
    else:
        return jsonify({'message':'user does not exist'}),401
@app.route('/password_update', methods=['GET','POST'])
def password_update():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email=data['email']
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        user.remove()
        username=data['username']
        password=data['new_password']
        user = User(username=username)
        user.set_password(password)
        user.save()
        msg = Message(subject='Password updated', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = "Hey "+username+" your password updated successfully"
        mail.send(msg)
        return jsonify({'message': 'user password updated successfully'}),201
    else:
        return jsonify({'message': 'user not exist'}),401
@app.route('/display', methods=['GET','POST'])
@is_admin
def display():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    user= User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        users=User.query.all()
        arr=[]
        for user in users:
            lst=[{"id":user.id,"username":user.username,"role":user.role._name_}]
            arr.append(lst)
        return ({'users': arr}),201
    else:
        return jsonify({'message':'no access'}),401
@app.route('/task_assign',methods=['GET','POST'])
def task_assign():
    data = request.get_json()
    admin_username = data['admin_username']
    admin_password = data['admin_password']
    admin = User.query.filter_by(username=admin_username).first()
    if admin and admin.check_password(admin_password): 
        if admin.role==YourRole.admin:
            username=data['username']
            task=data['task']
            user=User.query.filter_by(username=username).first()
            if user and user.role==YourRole.user:
                tasks = Task(username=username,task=task,user_id=data['user_id'])
                existing_task= Task.query.filter_by(username=username).first()
                if existing_task:
                    return jsonify({'message':'task still pending'}),400
                tasks.assign()
                return jsonify({'message': 'task assigned successfully'}),201
                    
            else:
                return jsonify({'message':'the user you want to assign is not exist'}),400
        else:
            return jsonify({'message':'you do  not have access to assign task'}),401
    else:
        return jsonify({'message': 'User does not exist'}),401    
@app.route('/task_check',methods=['GET','POST'])
def check_task():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user= User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        tasks = Task.query.filter_by(username=username).first()
        if tasks:
            return tasks.task
        else:
            return jsonify({'message':'task not assigned'}),400
    else:
       return jsonify({'message':'user not exist'}),401
       
@app.route('/task_status',methods=['GET','POST'])
def task_staus():
    data = request.get_json()
    username = data['username']
    password=data['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        task=data['status']
        tasks = Task.query.filter_by(username=username).first()
        if tasks:
            if task=="Done" or task=="done":
                tasks.task="Done"
                tasks.remove()
                return jsonify({'message':'task done successfully'}),201
        else:
            return jsonify({'message':'task not assigned'}),400
    else:
        return jsonify({'message':'user not exist'}),401
@app.route('/task_comments',methods=['GET','POST'])
@is_admin
def task_comments():
    data = request.get_json()
    admin_username = data['admin_username']
    admin_password = data['admin_password']
    admin = User.query.filter_by(username=admin_username).first()
    if admin and admin.check_password(admin_password): 
            username=data['username']
            comment=data['comment']
            user=User.query.filter_by(username=username).first()
            if user and user.role==YourRole.user:
                comments = Comments(username=username,comment=comment,user_id=data['user_id'])
                existing_task= Task.query.filter_by(username=username).first()
                if existing_task:
                    comments.add()
                    return jsonify({'message':'comment added successfully'}),201
                else:
                    return jsonify({'message':'task still pending'}),400
            else:
                return jsonify({'message':'there is no user of such name'}),400
    else:
        return jsonify({'message':'admin not exist'}),401
if __name__ == '__main__':
    app.run(debug=True)