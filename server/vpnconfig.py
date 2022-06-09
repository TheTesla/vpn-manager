from flask import Flask
from flask import request
import subprocess as sp
import json

app = Flask(__name__)

ipadrrng = "10.23.42.0/24"

@app.route("/api/connectpeer", methods=['POST', 'GET', 'DELETE'])
def apiconnect():
    pubkey = request.args.get('pubkey', '')
    try:
        if request.method == 'DELETE':
            sp.check_output(['wg', 'set', 'wg0', 'peer', pubkey, 'remove'])
            return json.dumps({'success': True})
        if request.method == 'POST':
            sp.check_output(['wg', 'set', 'wg0', 'peer', pubkey, 'allowed-ips',
                ipadrrng])
            with open("publickey", 'r') as f:
                clientPubKey = f.read()
            return json.dumps({'success': True, 'pubkey': clientPubKey})
    except Exception as e:
        assert(e)
        pass

    return json.dumps({'success': False})


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

