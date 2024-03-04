from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token
from flask_jwt_extended import create_access_token


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'key for login form'
jwt = JWTManager(app)
from model import User,Task, Comments

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
        return jsonify({'message':'User already exist'})
    elif role!="admin" and role!="user":
        return jsonify({'message':'not a valid role'})
    user.save()
    return jsonify({'message': 'User registered successfully'})
@app.route('/login', methods=['GET','POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity='user_id')
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid username or password'})

@app.route('/delete', methods=['GET','POST'])
def delete():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        user.remove()
        return jsonify({'message': 'user data deleted successfully'})
    else:
        return jsonify({'message':'user does not exist'})
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
        return jsonify({'message': 'user data updated successfully'})
    else:
        return jsonify({'message': 'user not exist'})
@app.route('/display', methods=['GET','POST'])
def display():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user= User.query.filter_by(username=username).first()
    if user and user.check_password(password) and user.role == "admin":
        users=User.query.all()
        arr=[]
        for user in users:
            lst=[{"id":user.id,"username":user.username,"role":user.role}]
            arr.append(lst)
        return jsonify({'users': arr})
    else:
        return jsonify({'message':'no access'})
@app.route('/task_assign',methods=['GET','POST'])
def task_assign():
    data = request.get_json()
    admin_username = data['admin_username']
    admin_password = data['admin_password']
    admin = User.query.filter_by(username=admin_username).first()
    if admin and admin.check_password(admin_password): 
        if admin.role=="admin":
            username=data['username']
            task=data['task']
            user=User.query.filter_by(username=username).first()
            if user and user.role=="user":
                tasks = Task(username=username,role=user.role,task=task)
                existing_task= Task.query.filter_by(username=username).first()
                if existing_task:
                    return jsonify({'message':'task still pending'}) 
                tasks.assign()
                return jsonify({'message': 'task assigned successfully'})
                    
            else:
                return jsonify({'message':'the user you want to assign is not exist'})
        else:
            return jsonify({'message':'you do  not have access to assign task'})
    else:
        return jsonify({'message': 'User does not exist'})    
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
            return jsonify({'message':'task not assigned'}) 
    else:
       return jsonify({'message':'user not exist'})  
       
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
                tasks.assign()
                return jsonify({'message':'task done successfully'})
        else:
            return jsonify({'message':'task still pending'})
    else:
        return jsonify({'message':'user not exist'})
@app.route('/task_comments',methods=['GET','POST'])
def task_comments():
    data = request.get_json()
    admin_username = data['admin_username']
    admin_password = data['admin_password']
    admin = User.query.filter_by(username=admin_username).first()
    if admin and admin.check_password(admin_password): 
        if admin.role=="admin":
            username=data['username']
            comment=data['comment']
            user=User.query.filter_by(username=username).first()
            if user and user.role=="user":
                comments = Comments(username=username,comment=comment)
                existing_task= Task.query.filter_by(username=username).first()
                if existing_task:
                    comments.add()
                    return jsonify({'message':'comment added successfully'})
                else:
                    return jsonify({'message':'task still pending'})
            else:
                return jsonify({'message':'there is no user of such name'})
        else:
            return jsonify({'message':'do not have access'})
    else:
        return jsonify({'message':'admin not exist'})
if __name__ == '__main__':
    app.run(debug=True)