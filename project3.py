from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend

from flask import Flask, request

import sqlite3
from sqlite3 import Error
import uuid

import jwt
from datetime import datetime, timedelta

from argon2 import PasswordHasher



app = Flask(__name__)


# kid = str(uuid.uuid4())

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


def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return conn



def create_table(conn):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """

    sql_create_keys_table = """CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
    )""";


    try:
        c = conn.cursor()
        c.execute(sql_create_keys_table)
    except Error as e:
        print(e)



def insert_keys(conn, task):
    """
    Create a new task
    :param conn:
    :param task:
    :return:
    """

    sql = ' INSERT INTO keys(kid,key,exp) VALUES(?,?,?) '
    cur = conn.cursor()
    cur.execute(sql, task)
    conn.commit()

    return cur.lastrowid

def insert_user(conn, dict):
        """
        Create a new user in user table
        :param conn:
        :param dict (user info):
        :return:
        """
        password = dict["password"]
        ph = PasswordHasher()
        hash = ph.hash("s3kr3tp4ssw0rd")

        sql = ' INSERT INTO users(username,password_hash, email,date_registered,last_login) VALUES(?,?,?,?,?) '
        cur = conn.cursor()
        commit = (dict["username"],hash,dict["email"],datetime.utcnow(),datetime.utcnow() + timedelta(days=0, seconds=-20))
        cur.execute(sql, commit)
        conn.commit()
        return cur.lastrowid

def insert_auth_logs(conn, dict):
        """
        Create a new user in auth_logs table
        :param conn:
        :param dict (user info):
        :return:
        """

        sql = ' INSERT INTO auth_logs(request_ip,user_id) VALUES(?,?) '
        cur = conn.cursor()
        commit = ("localhost", 5)
        cur.execute(sql, commit)
        conn.commit()
        return cur.lastrowid

def select_all_tasks(conn):
    """
    Query all rows in the tasks table
    :param conn: the Connection object
    :return:
    """
    cur = conn.cursor()
    cur.execute("SELECT * FROM auth_logs")

    rows = cur.fetchall()

    for row in rows:
        print(row)

def delete_all_rows(conn):
    """
    Delete all rows in the tasks table
    :param conn: Connection to the SQLite database
    :return:
    """
    sql = 'DELETE FROM keys'
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()

def jwk_set():
    jwks = {
        "keys":[{
            "kty":"RSA",
            "kid":'b1111PERF',      # FIX: only the unexpired kid for jwt should go here... fix logic
            "use":"sig",
            "alg":"RS256",
            "n":jwt.utils.base64url_encode(public_key.public_numbers().n.to_bytes((public_key.public_numbers().n.bit_length()+7)//8,'big')).decode("utf-8"),
            "e":jwt.utils.base64url_encode(public_key.public_numbers().e.to_bytes((public_key.public_numbers().e.bit_length()+7)//8,'big')).decode("utf-8")
            }]
    }
    return jwks

def encode_auth_token(exp,kid):

    payload = {
        'exp': exp,
        'iat': datetime.utcnow()
    }
    encoded_token = jwt.encode(
        payload,
        private_key,
        algorithm='RS256',
        headers={"kid": kid,
                "name": "userABC",
                "password": "password123",
                }
    )
    return encoded_token

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, public_key,  algorithms=["RS256"])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'



@app.route("/")
def home():
    return "Hello! <h1>Main page<h1>"

# @app.route("/register")
# def login():
    # pass

@app.route("/auth", methods = ['POST'])
def jwt_ret():
    code = 200
    expired = request.args.get('expired')
    data = request.json

    if expired == 'true':
        code = 401
        kid = 'a2223EX'
        exp = datetime.utcnow() + timedelta(days=0, seconds=-20)
    else:
        code = 200
        kid = 'b1111PERF'
        exp = datetime.utcnow() + timedelta(days=0, seconds=200)

    token = encode_auth_token(exp, kid)
    connection = create_connection(r"totally_not_my_privateKeys.db")
    insert_auth_logs(connection, data)

    return str(token), code

@app.route("/.well-known/jwks.json", methods = ['GET'])
def jwk_ret():
    return jwk_set()        # returns set

@app.route("/register", methods = ['POST'])
def register():
    code = 200
    data = request.json
    password = {"password": uuid.uuid4()}
    data = {**data, **password}
    connection = create_connection(r"totally_not_my_privateKeys.db")
    insert_user(connection, data)
    return password, code



if __name__ == "__main__":
    connection = create_connection(r"totally_not_my_privateKeys.db")
    # create_table(connection);
    # connection.execute("DROP TABLE auth_logs")
    if connection is not None:
        delete_all_rows(connection)
        task = ((1111, private_key, (int(round(datetime.now().timestamp()))-100)))
        insert_keys(connection,task)
        task = ((2222, private_key, int(round(datetime.now().timestamp())) + int(round(datetime.now().timestamp()))+10000))
        insert_keys(connection,task)

    else:
        print("Error! Cannot create the database connection")

    app.run(debug=True, host='localhost', port=8080)        # run app on port 8080
