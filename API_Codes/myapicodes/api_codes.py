import uuid
from functools import wraps
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, make_response, json, session
import jwt
from flask_sqlalchemy import SQLAlchemy
from API_Codes.myapicodes.model.dbconnect import User, Clientinfo
from API_Codes.myapicodes.model.connectionstring import db


APP = Flask(__name__)

APP.config['SECRET_KEY'] = '\x17H\xb4\x1d\xa4\xa59VC\xc7\xe2d;O\xb1\xb9\xb4\x04\xdeM#\x8d\x9e\x03'
APP.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
APP.config["SQLALCHEMY_DATABASE_URI"] = \
    'postgresql://clementbatie:deworma@localhost:5432/discover_flask_dev'
DATABASE_CONNECTION = SQLAlchemy(APP)


def token_required(value):

    @wraps(value)
    def decorated(*args, **kwargs):

        token = request.args.get('token')

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'': ' '}), 401

        try:
            data = jwt.decode(token, APP.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'': ' '}), 401

        return value(current_user, *args, **kwargs)

    return decorated


@APP.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:

        return jsonify({'message': 'Cannot perform that function'})

    users = User.query.all()

    output = []

    for user in users:

        user_data = {}

        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        output.append(user_data)

    return jsonify({'users': output})


@APP.route('/user/<public_id>', methods=['GET'])
@token_required
def get_single_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify({'user': user_data})


@APP.route('/user', methods=['POST'])
@token_required
def create_users(current_user):
    auth = request.data
    info = json.loads(auth)
    # username = info['username']
    # password = info['password']

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    hashed_password = generate_password_hash(info['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=info['username'],
                    password=hashed_password, admin=False)
    DATABASE_CONNECTION.session.add(new_user)
    DATABASE_CONNECTION.session.commit()

    return jsonify({'message': 'New user created!'})


@APP.route('/user/<public_id>', methods=['PUT'])
@token_required
def change_user_status(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    DATABASE_CONNECTION.session.commit()

    return jsonify({'message': 'User has been promoted'})


@APP.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    DATABASE_CONNECTION.session.delete(user)
    DATABASE_CONNECTION.session.commit()

    return jsonify({'message' : 'The user has been deleted'})


@APP.route('/login', methods=['POST'])
def login():
    auth = request.data
    info = json.loads(auth)
    global USERNAME
    USERNAME = info['username']
    password = info['password']

    if not auth or not USERNAME or not password:
        return make_response('Could not verify', 401,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=USERNAME).first()

    if not user:
        return make_response('Could not verify', 401,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if check_password_hash(user.password, password):
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30)},
                           APP.config['SECRET_KEY'])
        session.clear()
        return jsonify({'token': token.decode('UTF-8'),
                        'username': USERNAME, 'admin': user.admin})
    session.clear()
    return make_response('Could not verify', 401,
                         {'WWW-Authenticate': 'Basic realm="Login required!"'})


@APP.route('/logout', methods=['POST'])
def logout():
    # auth = request.data
    user_name = USERNAME
    # password = info['password']
    session.pop(user_name)
    user = User.query.filter_by(name=user_name).first()

    user.is_active = False
    db.session.commit()
    session.clear()

    # session.pop(user_name)
    return jsonify({'token': 'logged', 'user': user_name})


@APP.route('/allclients', methods=['GET'])
# @token_required
def get_all_clients():

    all_clients = Clientinfo.query.all()

    output = []

    for todo in all_clients:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['clientname'] = todo.clientname
        todo_data['accountnumber'] = todo.accountnumber
        todo_data['amount'] = str(todo.amount)
        todo_data['numberoftran'] = todo.numberoftran
        todo_data['gender'] = todo.gender
        output.append(todo_data)

    return jsonify({'clients': output})


@APP.route('/clientinfo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = Clientinfo(clientname=data['name'],
                          accountnumber=data['number'], amount=data['amount'],
                          numoftran=data['transaction'], gender=data['gender'],
                          userid=current_user.id)
    DATABASE_CONNECTION.session.add(new_todo)
    DATABASE_CONNECTION.session.commit()

    return jsonify({'message': 'Client Information Created!'})


if __name__ == '__main__':
    APP.run(debug=True)
