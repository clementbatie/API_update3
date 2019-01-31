from flask import Flask, request, jsonify, make_response,json
from flask_sqlalchemy import SQLAlchemy
from API_Codes.myapicodes.model.connectionstring import db

app = Flask(__name__)

# app = Flask("__name__")
# app.config['SECRET_KEY'] = '\x17H\xb4\x1d\xa4\xa59VC\xc7\xe2d;O\xb1\xb9\xb4\x04\xdeM#\x8d\x9e\x03'
# app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
# app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql://clementbatie:deworma@localhost:5432/discover_flask_dev'
# db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=False)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

    def __init__(self, public_id, name, password, admin):
        self.public_id = public_id
        self.name = name
        self.password = password
        self.admin = admin


class Clientinfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clientname = db.Column(db.String(50))
    accountnumber = db.Column(db.String(50))
    amount = db.Column(db.Numeric(10,2))
    numberoftran = db.Column(db.String(50))
    gender = db.Column(db.String(50))
    user_id = db.Column(db.Integer)

    def __init__(self, clientname, accountnumber, amount, numoftran, gender, userid):
        self.clientname = clientname
        self.accountnumber = accountnumber
        self.amount = amount
        self.numberoftran = numoftran
        self.gender = gender
        self.user_id = userid

db.create_all()