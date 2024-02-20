from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
import datetime
from functools import wraps
import os
from os.path import join, dirname
from flask_cors import CORS,cross_origin
from dotenv import load_dotenv
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)




app = Flask(__name__, static_folder='templates')
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
# cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
CORS(app)
def token_required(f):
    """
    Decorator function that verifies the presence of a valid JWT token in the request's headers.
    If the token is valid, it decodes it and retrieves the username from the decoded payload.
    The username is then passed as a parameter to the decorated function.
    If the token is invalid or missing, the decorated function is not executed and an appropriate response is sent to the client.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = None
            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']
            if not token:
                return jsonify({'message': 'Token is missing!'}), 401
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = data['username']
            except:
                return jsonify({'message': 'Token is invalid!'}), 401
            return f(current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

    return decorated


def get_db_connection():
    try:
        conn = sqlite3.connect('users.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


@app.route('/register', methods=['POST'])
@cross_origin()
def register_user():
    try:
        data = request.get_json()
        username = data['username']
        password = generate_password_hash(data['password'])
        print(username, password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Username already exists'}), 400
        finally:
            conn.close()

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


@app.route('/login', methods=['POST'])
@cross_origin()
def login_user():
    try:
        auth = request.authorization
        print(auth.username, auth.password)
        if not auth or not auth.username or not auth.password:
            return jsonify({'message': 'Could not verify'}), 401

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (auth.username,)).fetchone()
        conn.close()
        print(user['username'], user['password'], check_password_hash(user['password'], auth.password))
        if not user or not check_password_hash(user['password'], auth.password):
            return jsonify({'message': 'Could not verify'}), 401

        token = jwt.encode({'username': user['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        print(token)
        return jsonify({'token': token})
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


@app.route('/protected', methods=['GET'])
@cross_origin()
@token_required
def protected_route(current_user):
    try:
        return jsonify({'message': f'Welcome {current_user}! This is a protected route.'})
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


@app.route('/')
@cross_origin()
def index():
    try:
        return send_from_directory(app.static_folder, 'index.html')
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)