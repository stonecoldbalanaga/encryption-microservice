
from flask import Flask,request,jsonify
from flasgger import Swagger
from src.security.auth import auth
from src.services.aes_service import AESService
from src.services.rsa_service import RSAService
from src.services.hash_service import *
app=Flask(__name__); Swagger(app)

@app.get('/health')
def health(): return {'status':'UP'}

@app.post('/api/v1/aes/key')
@auth.login_required
def aes_key(): return {'key':AESService.generate_key()}

@app.post('/api/v1/aes/encrypt')
@auth.login_required
def aes_enc():
    d=request.json
    return jsonify(AESService.encrypt(d['message'],d['key']))

@app.post('/api/v1/aes/decrypt')
@auth.login_required
def aes_dec():
    d=request.json
    return {'message':AESService.decrypt(d['ciphertext'],d['nonce'],d['key'])}

@app.post('/api/v1/rsa/keys')
@auth.login_required
def rsa_keys():
    priv,pub=RSAService.generate_keys()
    return {'privateKey':priv,'publicKey':pub}

@app.post('/api/v1/rsa/encrypt')
@auth.login_required
def rsa_enc():
    d=request.json
    return {'ciphertext':RSAService.encrypt(d['message'],d['publicKey'])}

@app.post('/api/v1/rsa/decrypt')
@auth.login_required
def rsa_dec():
    d=request.json
    return {'message':RSAService.decrypt(d['ciphertext'],d['privateKey'])}

@app.post('/api/v1/hash/sha256')
@auth.login_required
def sha256():
    return {'hash':sha256_hash(request.json['message'])}

@app.post('/api/v1/hash/sha512')
@auth.login_required
def sha512():
    return {'hash':sha512_hash(request.json['message'])}

@app.post('/api/v1/hash/md5')
@auth.login_required
def md5():
    return {'hash':md5_hash(request.json['message'])}

if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000)
