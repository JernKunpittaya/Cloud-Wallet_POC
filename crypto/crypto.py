from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import flask
import flask_cors
import os
from fastecdsa import curve, ecdsa, keys
import base64

app = flask.Flask(__name__)
cors = flask_cors.CORS()
cors.init_app(app)


@app.route('/crypto/')
def hello_world():
    '''
    Returns the text to make sure this API is running.
    '''
    return 'Hello, Jern this is eciespy!'


@app.route('/eciespy/encrypt', methods=['POST'])
def encrypt_eciespy():
    '''
    Returns json of the string of encrypted data with eciespy with secp256k1

            Parameters:
                    pk_hex (hex string): hex string of eciespy public key
                    data (string): string of data that we want to encrypt

            Returns:
                    json: {'encrypted': string of encrypted data}
    '''
    pk_hex = flask.request.get_json(force=True).get('pk_hex')
    data = flask.request.get_json(force=True).get('data')
    # note that encrypt() outputs byte data, so we encode it with base64 into
    # a better form of byte and then decode('ascii') to make it string to send through json
    return {"encrypted": base64.b64encode(encrypt(pk_hex, data.encode('ascii'))).decode('ascii')}


@app.route('/eciespy/decrypt', methods=['POST'])
def decrypt_eciespy():
    '''
    Returns json of the string of decrypted data with eciespy

            Parameters:
                    sk_hex (hex string): hex string of eciespy secret key
                    data (string): string of data that we want to decrypt

            Returns:
                    json: {'decrypted': string of decrypted data}
    '''
    sk_hex = flask.request.get_json(force=True).get('sk_hex')
    data = flask.request.get_json(force=True).get('data')
    # In this POC, we expect decrypt to output byte of readable string, so no
    # need to encode with base 64 before decode('ascii'), prone to change if
    # to include base64 step if we want more generalization
    return {"decrypted": (decrypt(sk_hex, base64.b64decode(data.encode('ascii')))).decode('ascii')}


@app.route('/ecdsa/sign', methods=['POST'])
def sign_ecdsa():
    '''
    Returns json of the string of key_r and key_s for ecdsa with secp256r1

            Parameters:
                    private_sign (int string): int string of private key for fastecdsa
                    data (string): string of data that we want to sign

            Returns:
                    json: {'key_r': string of key_r of digital signature,'key_s': string of key_s of digital signature}
    '''
    private_sign = flask.request.get_json(force=True).get('private_sign')
    data = flask.request.get_json(force=True).get('data')
    # set curve to be secp256r1 to match Finema's
    r, s = ecdsa.sign(data, int(private_sign), curve=curve.brainpoolP256r1)
    return {"key_r": str(r), "key_s": str(s)}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 7777)))
