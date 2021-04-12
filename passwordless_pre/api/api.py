import os
import time
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import flask_cors
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
from fastecdsa import curve, ecdsa, keys, point
import base64
import requests
import json
from umbral import pre
# initialization
app = Flask(__name__)

# secret key for using with JWT
app.config['SECRET_KEY'] = 'Very secret key of Alice cloud wallet'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()
cors = flask_cors.CORS()

# secret key of Alice's cloud wallet via eciespy
sk_server = "0xc60d216e58ca0eff4f2993195beb6f082c9fbe63ce89b93d368f7984e1eb84af"
# encrypted resource of Alice via Alice's umbral public key (Alice's cloud wallet cannot decrypt this message because it does not have Alice's umbral secret key)
secret_text = "Q8D2/1prK6igVJvOGZHI3Po/qA2L1wO9tX2V7qL0LdDiAM28UdA/w7YsjcnKJM4FyQeQtXOmmVi/QzV7C9jNCwpF"
# string of the related capsule to the secret_text that was encrypted with Alice's umbral public key
capsule_string = "A//z4cMoU4ZP/tcuUKA9qZRtO7CLy2VHlACOILZM9eWCA1aBFgAehvy93X5zYkkvjAWqQpKOl4CUOUx1EjR/9yUcSi94QJTm9VFrrqwrg/B3fCiLoYvKR8STpNO23BJkg6k="


class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(128), primary_key=True)
    public_sign1 = db.Column(db.String(128))
    public_sign2 = db.Column(db.String(128))

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.username, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])


@auth.verify_password
def verify_password(username_or_token, password):
    '''
    This method is adjusted from the typical username/password verification but we 
    adjust it to only verify the token (no need for password)
    '''
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password (which is not necessary in our case, can delete two lines below, leaving only return False statement)
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    return True


# Register the authorized user of this cloud wallet (Alice)
# Register with Alice's did (which we represent with Alice's eciespy public key), public_sign1, public_sign2 for verifying the digital signature from Alice
# Note that we abstract registration process in this POC and hard code the following Alice's info as if Alice has done identity proving successfully
db.init_app(app)
cors.init_app(app)
with app.app_context():
    db.create_all()
    if db.session.query(User).filter_by(username="0xc962736683a565d12dbc299b5a17d97fe53137af2a151766c741d5fbb1d1a873594c648f28702a01b7588d895c56763859e52d31c62abf9deb15659b497c9928").count() < 1:
        db.session.add(User(
            username="0xc962736683a565d12dbc299b5a17d97fe53137af2a151766c741d5fbb1d1a873594c648f28702a01b7588d895c56763859e52d31c62abf9deb15659b497c9928",
            public_sign1="0x947599fe125266e93f2333cdc58ca61d4f6bcdcf12ee889632bac298a5d64c5",
            public_sign2="0x8dc63a6fd1ceef6cf3bbee9d0738762ce6e0af9bdd6c106abff5940a101cab30"
        ))
    db.session.commit()


@app.route('/api/')
def hello():
    '''
    Returns the json to make sure this API is running.
    '''
    return jsonify({'name': "Hello Jernjaa"})


@app.route('/api/users/<string:id>')
def get_user(id):
    '''
    NOT necessary: returns cloud's owner info.
    '''
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username, 'key1': user.public_sign1, 'key2': user.public_sign2})


@app.route('/api/requesttoken', methods=['POST'])
def request_token():
    '''
    Returns json of the encrypted token for authenticating into Alice's cloud wallet

            Parameters:
                    username (string): encrypted Alice's local wallet did
                    key_r (string): encrypted key_r for Alice's signature by ecdsa
                    key_s (string): encrypted key_s for Alice's signature by ecdsa

            Returns:
                    json: {'token': encrypted token} (if successfully authenticated)
    '''
    req = request.get_json(force=True)
    username = req.get('username', None)
    key_r = req.get('key_r', None)
    key_s = req.get('key_s', None)
    username = decrypt(sk_server, base64.b64decode(
        username.encode('ascii'))).decode('ascii')
    key_r = int((decrypt(sk_server, base64.b64decode(
        key_r.encode('ascii')))).decode('ascii'))
    key_s = int((decrypt(sk_server, base64.b64decode(
        key_s.encode('ascii')))).decode('ascii'))
    # look up whether the request did is in cloud wallet database
    user = User.query.get(username)
    if not user:
        abort(403, description="User not found")
    # check digital signature
    public_sign = point.Point(
        int(user.public_sign1, 16), int(user.public_sign2, 16), curve=curve.brainpoolP256r1)
    valid = ecdsa.verify((key_r, key_s), username,
                         public_sign, curve=curve.brainpoolP256r1)
    if valid == False:
        abort(403, description="signature tampered")
    token = user.generate_auth_token(600)
    token_encrypt = str(base64.b64encode(encrypt(
        user.username, token.encode('ascii'))).decode('ascii'))
    return jsonify({'token': token_encrypt, 'duration': 600})


@app.route('/api/connected')
@auth.login_required
def check_connect():
    '''
    Return json to inform that Alice's local wallet successfully connect to her own cloud wallet
    '''
    return jsonify({'data': "Connected to cloud agent successfully"})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    '''
    When the request is authorized, return the corresponding encrypted data and capsule from the cloud wallet.
    '''
    return jsonify({'data': secret_text, 'capsule': capsule_string})


@app.route('/api/sendToBob', methods=['POST'])
@auth.login_required
def send_Bob():
    '''
    When the request is authorized, send the encrypted Alice's data (with Umbral) from Alice's cloud wallet to Bob's cloud wallet
    as well as neceesary material for Bob to decrypt via proxy re encryption. 
            Parameters:
                    verifying_string (string): encrypted Alice's local wallet did
                    kfrag_string (string): encrypted key_r for Alice's signature by ecdsa


            Returns:
                    json:  {'name': 'send to Bob successfully'} (if successfully sent)
    '''
    req = request.get_json(force=True)
    verifying_string = req.get('verifying_string', None)
    kfrag_string = req.get('kfrag_string', None)
    url = "http://host.docker.internal:5555/apibob/sendData"
    payload = {'ciphertext': secret_text,
               'capsule_string': capsule_string,
               'kfrag': kfrag_string,
               'verifying_string': verifying_string}
    response = requests.post(url, json=payload)
    return response.json()


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
