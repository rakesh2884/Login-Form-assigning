from __main__ import app
from functools import wraps
from flask import request, jsonify
from model import User, YourRole
def is_admin(f):
    @wraps(f)
    def inner(*args, **kwargs):
        data=request.get_json()
        username=data['username']
        password=data['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.role==YourRole.admin:
                return f(*args, **kwargs)
            else:
                return jsonify({'message':'no access'}),401
        else:
            return jsonify({'message':'Invalid User'}),401
    return inner
def is_user(f):
    @wraps(f)
    def inner(*args, **kwargs):
        data=request.get_json()
        username=data['username']
        password=data['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.role==YourRole.user:
                return f(*args, **kwargs)
            else:
                return jsonify({'message':'no access'}),401
        else:
            return jsonify({'message':'Invalid User'}),401
    return inner