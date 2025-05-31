from flask import Flask, session, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_restful import Api, Resource
import os



app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user_test.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'super-secret-key')
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

api = Api(app)
CORS(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
