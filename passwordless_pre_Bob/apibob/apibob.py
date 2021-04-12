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
from fastecdsa import curve, ecdsa, keys
import fastecdsa.point as ecdsa_point
import base64
from umbral import kfrags, pre, keys, params, config, cfrags, curvebn, point
from umbral.curve import SECP256R1
from cryptography.hazmat.backends.openssl import backend
# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Such a latent secret key of Bob cloud wallet'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
config.set_default_curve(SECP256R1)
# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()
cors = flask_cors.CORS()

# secret key of Alice's cloud wallet via eciespy
sk_server_Bob = "0xc1538febd2c058fe9a4ad3525430e0b95776ee85f01bd163c1f4802df0725db8"
# encrypted resource of Bob via Bob's umbral public key (Alice's cloud wallet cannot decrypt this message because it does not have Bob's umbral secret key)
secret_text_Bob = "8r7I3vP6WxIVdm5CdZQyI59HlHb3GRPrqnjfoObb0gzL3kGY/kIdbFK9Q24vFaKK0Lk4jJGvFSG6cL+QPVTQ2g=="
# string of the related capsule to the secret_text that was encrypted with Bob's umbral public key
capsule_string_Bob = "AukH/hsasKkqgv87gcbB9QHXPNTwZqy0nhgkDK4A2PRwA+yRYNSBY3gWEqcBi02iMHnzGWA5HTQIZH9Q7ic4PrwZ7khzeupGC9O14+CkU+b7O6OlEFeRHSKtlcdywVK0GT0="
# encrypted Alice's data resource with Alice's umbral public key (sent from Alice's cloud wallet to Bob's cloud wallet)
ciphertext_Alice_string = "Not received cipher"
# capsule for ciphertext_Alice_string, needed for Bob to decrypt proxy re encryption
Capsule_Alice = "No Alice Capsule"
# kfrag of Alice's proxy re encryption, needed for Bob to decrypt proxy re encryption
k_frag_Alice = "No Alice kfrag"
# verifying string used to verify whether k_frag is tampered or not
verifying_Alice_string = "No Alice verifying"


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
# Register with Bob's did (which we represent with Bob's eciespy public key), public_sign1, public_sign2 for verifying the digital signature from Bob
# Note that we abstract registration process in this POC and hard code the following Bob's info as if Bob has done identity proving successfully
db.init_app(app)
cors.init_app(app)
with app.app_context():
    db.create_all()
    if db.session.query(User).filter_by(username="0x7fb36db75a49cc7b14011d1b88623749f33da2aa45b328aa4854337a0c0e7656241f14d56e2e91f8cbbc4d6fdc2cf3462bcfa1f14f79d537c3e58380f204c730").count() < 1:
        db.session.add(User(
            username="0x7fb36db75a49cc7b14011d1b88623749f33da2aa45b328aa4854337a0c0e7656241f14d56e2e91f8cbbc4d6fdc2cf3462bcfa1f14f79d537c3e58380f204c730",
            public_sign1="0x7c9eef372063e609b9662b8ddb5d663c5a54ebd75c166ba8a811de9728615559",
            public_sign2="0x4fe08a04cb51549721b08f812d690149d554779dd232a16cf1ae60bb52a3c334"
        ))
    db.session.commit()


@app.route('/apibob/')
def hello():
    '''
    Returns the json to make sure this API is running.
    '''
    return jsonify({'name': "Hello Here is Bob"})


@app.route('/apibob/users/<string:id>')
def get_user(id):
    '''
    NOT necessary: returns cloud's owner info.
    '''
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username, 'key1': user.public_sign1, 'key2': user.public_sign2})


@app.route('/apibob/requesttoken', methods=['POST'])
def request_token():
    '''
    Returns json of the encrypted token for authenticating into Bob's cloud wallet

            Parameters:
                    username (string): encrypted Bob's local wallet did
                    key_r (string): encrypted key_r for Bob's signature by ecdsa
                    key_s (string): encrypted key_s for Bob's signature by ecdsa

            Returns:
                    json: {'token': encrypted token} (if successfully authenticated)
    '''
    req = request.get_json(force=True)
    username = req.get('username', None)
    key_r = req.get('key_r', None)
    key_s = req.get('key_s', None)
    username = decrypt(sk_server_Bob, base64.b64decode(
        username.encode('ascii'))).decode('ascii')
    key_r = int((decrypt(sk_server_Bob, base64.b64decode(
        key_r.encode('ascii')))).decode('ascii'))
    key_s = int((decrypt(sk_server_Bob, base64.b64decode(
        key_s.encode('ascii')))).decode('ascii'))
    # look up whether the request did is in cloud wallet database
    user = User.query.get(username)
    if not user:
        abort(403, description="User not found")
    # check digital signature
    public_sign = ecdsa_point.Point(int(user.public_sign1, 16), int(
        user.public_sign2, 16), curve=curve.brainpoolP256r1)
    valid = ecdsa.verify((key_r, key_s), username,
                         public_sign, curve=curve.brainpoolP256r1)
    if valid == False:
        abort(403, description="signature tampered")
    token = user.generate_auth_token(600)
    token_encrypt = str(base64.b64encode(encrypt(
        user.username, token.encode('ascii'))).decode('ascii'))
    return jsonify({'token': token_encrypt, 'duration': 600})


@app.route('/apibob/connected')
@auth.login_required
def check_connect():
    '''
    Return json to inform that Bob's local wallet successfully connect to her own cloud wallet
    '''
    return jsonify({'data': "Connected to cloud agent successfully"})


@app.route('/apibob/resource')
@auth.login_required
def get_resource():
    '''
    When the request is authorized, return the corresponding encrypted data and capsule from the cloud wallet.
    '''
    return jsonify({'data': secret_text_Bob, 'capsule': capsule_string_Bob})


@app.route('/apibob/sendData', methods=['POST'])
def sendData_pre():
    '''
    Update the value of relevant material sent from Alice's cloud walelt to perform decryption of proxy re encryption later

            Parameters:
                    ciphertext (string): encrypted Alice's resource by Alice's umbral public key
                    capsule_string (string): related capsule to ciphertext
                    kfrag (string): kfrag (necessary for Bob to decrypt the ciphertext and proxy re encryption key
                    verifying_string (string): to verify whether kfrag is tampered or not

            Returns:
                    json: {'name': 'send to Bob successfully'}
    '''
    global ciphertext_Alice_string
    global Capsule_Alice
    global k_frag_Alice
    global verifying_Alice_string
    req = request.get_json(force=True)
    ciphertext_Alice_string = req.get('ciphertext', None)
    Capsule_Alice = req.get('capsule_string', None)
    k_frag_Alice = req.get('kfrag', None)
    verifying_Alice_string = req.get('verifying_string', None)
    return jsonify({'name': 'send to Bob successfully'})


@app.route('/apibob/getAliceData')
@auth.login_required
def getAliceData_pre():
    '''
    When the request is authorized, return the Alice's
    ciphertext and necessary material to decrypt with umbral (proxy re encryption)
    '''
    return jsonify({
        'ciphertext': ciphertext_Alice_string,
        'capsule': Capsule_Alice,
        'k_frag': k_frag_Alice,
        'verifying_alice': verifying_Alice_string
    })


@app.route('/apibob/deleteAliceData')
@auth.login_required
def deleteAliceData():
    '''
    When the request is authorized, delete the Alice's
    ciphertext and necessary material to decrypt with umbral (proxy re encryption)
    from this Bob's cloud wallet
    '''
    global ciphertext_Alice_string
    global Capsule_Alice
    global k_frag_Alice
    global verifying_Alice_string
    ciphertext_Alice_string = "Not received cipher"
    Capsule_Alice = "No Alice Capsule"
    k_frag_Alice = "No Alice kfrag"
    verifying_Alice_string = "No Alice verifying"
    return {"return": "no return"}


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5555)))
