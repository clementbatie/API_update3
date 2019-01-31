from flask import Flask, request, jsonify, make_response,json
from flask_sqlalchemy import SQLAlchemy

app = Flask("__name__")
app.config['SECRET_KEY'] = '\x17H\xb4\x1d\xa4\xa59VC\xc7\xe2d;O\xb1\xb9\xb4\x04\xdeM#\x8d\x9e\x03'
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql://clementbatie:deworma@localhost:5432/discover_flask_dev'
db = SQLAlchemy(app)