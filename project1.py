from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend

from flask import Flask, request

from datetime import datetime, timedelta
import uuid
import jwt


valid_keys = []

key = rsa.generate_private_key(
    backend=crypto_default_backend(),
    public_exponent=65537,
    key_size=2048
)

private_key = key.private_bytes(            # sets private key based on rsa generated key
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.NoEncryption()
)

public_key = key.public_key()               # sets public key based on rsa generated key


app = Flask(__name__)


def jwk_set():                              # create key sets
    for i in valid_keys:                    # using only key id (since i am not changing the actual keys)
        keys = {
        "kty":"RSA",
        "kid":i,      # FIX: only the unexpired kid for jwt should go here... fix logic
        "use":"sig",
        "alg":"RS256",
        "n":jwt.utils.base64url_encode(public_key.public_numbers().n.to_bytes((public_key.public_numbers().n.bit_length()+7)//8,'big')).decode("utf-8"),
        "e":jwt.utils.base64url_encode(public_key.public_numbers().e.to_bytes((public_key.public_numbers().e.bit_length()+7)//8,'big')).decode("utf-8")
        }

    jwks = {
        "keys":[
            keys
            ]
    }
    return jwks



def encode_auth_token(exp,kid):
    payload = {
        "name": "userABC", 
        "password": "password123",
        'exp': exp,
        'iat': datetime.utcnow()
    }
    encoded_token = jwt.encode(
        payload,
        private_key,
        algorithm='RS256',
        headers={"kid": kid,
                "alg":'RS256'
                }
    )
    return encoded_token





@app.route("/")                             # Main landing page
def home():
    return "Hello! <h1>Main page<h1>"


@app.route("/auth", methods = ['POST'])
def jwt_ret():
    expired = request.args.get('expired')   # Retrives "expired" tag from request
    
    if expired == 'true':
        code = 401          # expired
        kid = str(uuid.uuid4())
        exp = datetime.utcnow() + timedelta(days=0, seconds=-20)
    else:
        code = 200          # valid
        kid = str(uuid.uuid4())
        valid_keys.append(kid)
        exp = datetime.utcnow() + timedelta(days=0, seconds=200)
    
    token = encode_auth_token(exp, kid)

    return str(token), code # returs jwt and http code


@app.route("/.well-known/jwks.json", methods = ['GET'])
def jwk_ret():
    return jwk_set()        # returns valid jason web key set

    
if __name__ == "__main__":
    
    app.run(debug=True, host='localhost', port=8080)        # run app on port 8080
