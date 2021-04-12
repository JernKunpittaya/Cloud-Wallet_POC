from umbral import pre, keys, config, curvebn, params, openssl, signing, point, kfrags, cfrags
from umbral.curve import SECP256R1
from cryptography.hazmat.backends.openssl import backend
import flask
import flask_cors
import os
import base64

app = flask.Flask(__name__)
cors = flask_cors.CORS()
cors.init_app(app)
config.set_default_curve(SECP256R1)


@app.route('/umbral/')
def hello_world():
    '''
    Returns the text to make sure this API is running and connected.
    '''
    return 'Hello, Jern this is umbral!'


@app.route('/umbral/decrypt', methods=['POST'])
def decrypt_umbral():
    '''
    Returns json of the decrypted text 

            Parameters:
                    sk_hex (string): essence of Alice's umbral secret key to recreate the actual Alice's umbral secret key
                    cipher_text(string): Alice's resource encrypted with Alice's umbral public key
                    capsule_text (string): essence of cipher_text's capsule to recreate the actual capsule
            Returns:
                    json: {'decrypted': decrypted string} (if successfully decrypted)
    '''
    sk_hex = int(flask.request.get_json(force=True).get('sk_hex'), 0)
    cipher_text = flask.request.get_json(force=True).get('cipher_text')
    capsule_text = flask.request.get_json(force=True).get('capsule_text')
    sk_real = keys.UmbralPrivateKey(curvebn.CurveBN(backend._int_to_bn(
        sk_hex), SECP256R1), params.UmbralParameters(SECP256R1))
    capsule_byte = base64.b64decode(capsule_text.encode('ascii'))
    capsuleSync = pre.Capsule.from_bytes(
        capsule_byte, params.UmbralParameters(SECP256R1))
    ciphertext = base64.b64decode(cipher_text.encode('ascii'))
    cleartext = pre.decrypt(ciphertext=ciphertext,
                            capsule=capsuleSync, decrypting_key=sk_real)
    return {"decrypted": cleartext.decode('ascii')}


@app.route('/umbral/reencrypt', methods=['POST'])
def reencrypt_umbral():
    '''
    Returns json of the kfrag (re encryption key) and its essence of verifying string 

            Parameters:
                    sk_hex (string): essence of Alice's umbral secret key to recreate the actual Alice's umbral secret key
                    pk_reencrypt(string): essence of Bob's umbral public key to recreate the actual Alice's umbral secret key
            Returns:
                    json: {'veriying_string': essence of verifying string for kfrags, 'kfrag_string': kfrag_string} 
    '''
    sk_hex = int(flask.request.get_json(force=True).get('sk_hex'), 0)
    bob_public_key_string = flask.request.get_json(
        force=True).get('pk_reencrypt')
    bob_public_key = keys.UmbralPublicKey(point.Point.from_bytes(base64.b64decode(
        bob_public_key_string.encode('ascii'))), params.UmbralParameters(SECP256R1))
    alices_signing_key = keys.UmbralPrivateKey.gen_key()
    alices_verifying_key = alices_signing_key.get_pubkey()
    alices_signer = signing.Signer(private_key=alices_signing_key)
    alices_verifying_string = (base64.b64encode(
        alices_verifying_key.to_bytes())).decode('ascii')
    alices_private_key = keys.UmbralPrivateKey(curvebn.CurveBN(backend._int_to_bn(
        sk_hex), SECP256R1), params.UmbralParameters(SECP256R1))
    kfrags = pre.generate_kfrags(delegating_privkey=alices_private_key, signer=alices_signer, receiving_pubkey=bob_public_key, threshold=1,
                                 N=1)
    kfrag_string = (base64.b64encode(
        (kfrags[0]).to_bytes())).decode('ascii')
    return {'verifying_string': alices_verifying_string, 'kfrag_string': kfrag_string}


@app.route('/umbral/decrypt_pre', methods=['POST'])
def decrypt_pre_umbral():
    '''
    Returns json of the decrypted text with re encryption key

            Parameters:
                    ciphertext (string): Alice's resource encrypted with Alice's umbral public key
                    capsule (string): essence of Alice's resource encrypted with Alice's umbral public key
                    verifying_alice (string): essence of verifying_alice for verifying alice's ciphertext
                    pk_umbral_Alice_string (string): essence of Alice's umbral public key
                    pk_umbral_Bob_string (string): essence of Bob's umbral public key
                    k_frag (string): essence of k_frags
                    sk_umbral_Bob_string (string): essence of Bob's umbral secret key


            Returns:
                    json: {'decrypted': decrypted string} (if successfully decrypted)
    '''
    req = flask.request.get_json(force=True)
    ciphertext_Alice_string = req.get('ciphertext')
    ciphertext_Alice = base64.b64decode(
        ciphertext_Alice_string.encode('ascii'))
    Capsule_Alice = req.get('capsule')
    capsule_byte = base64.b64decode(Capsule_Alice.encode('ascii'))
    capsuleSend = pre.Capsule.from_bytes(
        capsule_byte, params.UmbralParameters(SECP256R1))
    verifying_Alice_string = req.get('verifying_alice')
    alices_verifying_key = keys.UmbralPublicKey(point.Point.from_bytes(base64.b64decode(
        verifying_Alice_string.encode('ascii'))), params.UmbralParameters(SECP256R1))

    pk_umbral_Alice_string = req.get('pk_umbral_Alice_string')
    pk_umbral_Alice = keys.UmbralPublicKey(point.Point.from_bytes(base64.b64decode(
        pk_umbral_Alice_string.encode('ascii'))), params.UmbralParameters(SECP256R1))
    pk_umbral_Bob_string = req.get('pk_umbral_Bob_string')
    pk_umbral_Bob = keys.UmbralPublicKey(point.Point.from_bytes(
        base64.b64decode(pk_umbral_Bob_string.encode('ascii'))), params.UmbralParameters(SECP256R1))

    capsuleSend.set_correctness_keys(
        delegating=pk_umbral_Alice, receiving=pk_umbral_Bob, verifying=alices_verifying_key)

    k_frag_Alice = req.get('k_frag')

    kfrags_rec = kfrags.KFrag.from_bytes(
        base64.b64decode(k_frag_Alice.encode('ascii')), SECP256R1)
    cfrag = pre.reencrypt(kfrag=kfrags_rec, capsule=capsuleSend)
    capsuleSend.attach_cfrag(cfrag)

    sk_umbral_Bob_int = int(req.get('sk_umbral_Bob_string'), 0)
    sk_umbral_Bob = keys.UmbralPrivateKey(curvebn.CurveBN(
        backend._int_to_bn(sk_umbral_Bob_int), SECP256R1), config.default_params())
    cleartext = pre.decrypt(ciphertext=ciphertext_Alice,
                            capsule=capsuleSend, decrypting_key=sk_umbral_Bob)
    return {'cleartext': cleartext.decode('ascii')}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
