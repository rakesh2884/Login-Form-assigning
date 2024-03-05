from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token
from flask_jwt_extended import create_access_token
import os
import json
from functools import wraps
from flask import g, request, redirect, url_for
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
jwt = JWTManager(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

from model import User,Task, Comments,YourRole

def is_admin(f):
    @wraps(f)
    def inner(*args, **kwargs):
        user=User.query.all()
        if user[2]==YourRole.user:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return inner
def is_user(f):
    @wraps(f)
    def inner(*args, **kwargs):
        user=User.query.all()
        if user[2]==YourRole.admin:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return inner

@app.route('/register', methods=['GET','POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role=data['role']
    user = User(username=username,role=role)
    user.set_password(password)
    existing_user= User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message':'User already exist'}),201
    elif role!="admin" and role!="user":
        return jsonify({'message':'not a valid role'}),401
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

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        user.remove()
        username=data['username']
        password=data['new_password']
        user = User(username=username)
        user.set_password(password)
        user.save()
        return jsonify({'message': 'user data updated successfully'}),201
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
def task_comments():
    data = request.get_json()
    admin_username = data['admin_username']
    admin_password = data['admin_password']
    admin = User.query.filter_by(username=admin_username).first()
    if admin and admin.check_password(admin_password): 
        if admin.role==YourRole.admin:
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
            return jsonify({'message':'do not have access'}),401
    else:
        return jsonify({'message':'admin not exist'}),401
if __name__ == '__main__':
    app.run(debug=True)