from flask import Flask, request, jsonify, redirect, g
from flask_pymongo import PyMongo

from werkzeug.security import generate_password_hash, check_password_hash

from bson import json_util

from config import MONGO_URI
from auth import *


def create_app():
    app = Flask(__name__)
    app.config['MONGO_URI'] = MONGO_URI
    app.config['DEBUG'] = True

    app_context = app.app_context()
    app_context.push()

app = create_app()
mongo = PyMongo(app)

col_users = mongo.db.users
col_questions = mongo.db.questions

def authenticate(username, password):
    user = col_users.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        return user
    else:
        return None

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    user = authenticate(data['username'], data['password'])
    if user:
        token_payload = {'username': user['username']}
        return create_token(token_payload)
    else:
        return "Unauthorized", 401


@app.route('/', methods=['GET'])
@jwt_required
def index():
    res = col_users.find({})
    return json_util.dumps(list(res)), 200


# rota para visualizar o conteudo do payload encriptado no token.
@app.route('/token', methods=['GET'])
@jwt_required
def token():    
    return json_util.dumps(g.parsed_token), 200


@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    data['password'] = generate_password_hash(data['password'])
    col_users.insert_one(data)
    return 'usuario ' + data['username'] + ' criado.', 201

@app.route('/users/<username>', methods=['GET'])
def get_user(username):
    return username, 200

# rota para exemplificar como utilizar obter variaveis
# de url. teste acessando 
# http://localhost:8088/questions/search?disciplina=1 
@app.route('/questions/search', methods=['GET'])
def search():
    disciplina = request.args.get('disciplina')
    return disciplina, 200
