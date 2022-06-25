#!/usr/bin/env python3
from flask import Flask
from flask import request
from flask_httpauth import HTTPTokenAuth

import subprocess as sp
import json
import time
from threading import Thread


hostname = 'vpnserver'

def run(cli, input=None):
    return sp.check_output(cli, input=input)

def ip2value(ip):
    lbls = ip.split('/')[0].split('.')
    return sum([256**(len(lbls)-1-i) * int(x) for i,x in enumerate(lbls)])

def value2ip(val):
    lbls = ['','','','']
    for i in range(4):
        lbls[-1-i] = '{}'.format(int(val % 256))
        val = int(val / 256)
    return '.'.join(lbls)

def maskPart2val(ip):
    maskPart = int(str(ip).split('/')[-1])
    return 2**32-2**(32-maskPart)

def calcIpNet(ip):
    m = int(str(ip).split('/')[-1])
    return value2ip(ip2value(ip) & maskPart2val(ip)) + '/{}'.format(m)

def ipRng2set(ipStart, ipEnd, ipHost):
    m = maskPart2val(ipHost)
    ms = int(str(ipHost).split('/')[-1])
    h = ip2value(ipHost)
    s = ip2value(ipStart)
    e = ip2value(ipEnd) + 1
    if s > e:
        raise ValueError('IP range end before start')
    if (s & m) != (h & m):
        raise ValueError('IP range start violates netmask')
    if (e & m) != (h & m):
        raise ValueError('IP range end violates netmask')
    return {value2ip(x)+'/{}'.format(ms) for x in range(s,e) if x != h}



class PeerManager:
    def __init__(self):
        self.peers = {}

    def verify(self, token):
        if token not in self.peers:
            name = 'Peer_{}'.format(token[-8:])
            self.peers[token] = {'permit': False, 'name': name}
        if self.peers[token]['permit']:
            return self.peers[token]['name']

    def permit(self, token, allow=True):
        if token not in self.peers:
            name = 'Peer_{}'.format(token[-8:])
            self.peers[token] = {'permit': False, 'name': name}
        self.peers[token]['permit'] = allow
        return True

    def delete(self, token):
        del self.peers[token]


class VPNManager:
    def __init__(self, ip='10.23.42.1/24', port=51820, dev='wg0',
            dhcpStart='10.23.42.2', dhcpEnd='10.23.42.150', timeout=10):
        self.__enabled = False
        self.__clientDict = {}
        self.__timeout = timeout
        self.__alive = True
        self.__thrd = Thread(target=self.purgeTimeoutThrdFunc)
        self.__thrd.start()
        self.setConfig(ip, port, dev, dhcpStart, dhcpEnd, timeout)
        self.hostname = 'vpnserver'

    def setConfig(self, ip=None, port=None, dev=None, dhcpStart=None,
            dhcpEnd=None, timeout=None):
        if ip is not None:
            self.__ip = ip
            self.__ipRng = calcIpNet(ip)
        if port is not None:
            self.__port = port
        if dev is not None:
            self.__dev = dev
        if dhcpStart is not None:
            self.__dhcpStart = dhcpStart
        if dhcpEnd is not None:
            self.__dhcpEnd = dhcpEnd
        if timeout is not None:
            self.__timeout = timeout
        self.__ipSet = ipRng2set(dhcpStart, dhcpEnd, ip)
        self.__clientDict = {}
        self.__setupLink()

    def enable(self):
        self.__enabled = True
        self.__setupLink()

    def disable(self):
        self.__enabled = False
        self.__setupLink()

    def getPubKey(self):
        return self.__pubkey

    def getConfig(self):
        return {'ip' : self.__ip, 'iprng': self.__ipRng, 'port': self.__port,
                'dev': self.__dev, 'dhcpstart': self.__dhcpStart, 'dhcpend':
                self.__dhcpEnd, 'timeout': self.__timeout}

    def getIPRng(self):
        return self.__ipRng

    def getClientDict(self):
        return self.__clientDict

    def __setupLink(self):
        self.__rmLink()
        if self.__enabled == False:
            return
        self.__privkey = run(['wg', 'genkey']).replace(b'\n',b'')
        self.__pubkey = run(['wg', 'pubkey'],
                        input=self.__privkey).replace(b'\n', b'')
        run(['ip', 'link', 'add', 'dev', self.__dev, 'type', 'wireguard'])
        run(['ip', 'address', 'add', 'dev', self.__dev, self.__ip])
        run(['wg', 'set', self.__dev, 'listen-port', str(self.__port), 'private-key',
        '/dev/stdin'], input=self.__privkey)
        run(['ip', 'link', 'set', 'up', 'dev', self.__dev])

    def __rmLink(self):
        try:
            run(['ip', 'link', 'del', 'dev', self.__dev])
        except sp.CalledProcessError as e:
            pass


    def deleteClient(self, pubkey):
        if pubkey in self.__clientDict:
            self.__ipSet.add(self.__clientDict[pubkey]['ip'])
            del self.__clientDict[pubkey]
        run(['wg', 'set', self.__dev, 'peer', pubkey, 'remove'])

    def addClient(self, pubkey, user):
        if pubkey not in self.__clientDict:
            self.__clientDict[pubkey] = {}
            self.__clientDict[pubkey]['ip'] = self.__ipSet.pop()
            self.__clientDict[pubkey]['created'] = time.time()
            self.__clientDict[pubkey]['user'] = user
        self.__clientDict[pubkey]['renewed'] = time.time()
        run(['wg', 'set', self.__dev, 'peer', pubkey, 'allowed-ips',
            self.__ipRng])
        return self.__clientDict[pubkey]


    def checkClient(self, pubkey, user):
        if pubkey not in self.__clientDict:
            return None
        self.__clientDict[pubkey]['renewed'] = time.time()
        return self.__clientDict[pubkey]

    def purgeTimeout(self):
        t = time.time()
        for k, v in self.__clientDict.copy().items():
            age = t-v['renewed']
            if age > self.__timeout:
                self.deleteClient(k)

    def purgeTimeoutThrdFunc(self):
        while(self.__alive):
            time.sleep(1)
            self.purgeTimeout()

    def __del__(self):
        self.disable()
        self.__alive = False




app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')


vpn = VPNManager()
vpn.enable()


pm = PeerManager()



@auth.verify_token
def verify_token(token):
    return pm.verify(token)

@app.route("/api/permitpeer", methods=['GET', 'POST', 'DELETE'])
def apipermitpeer():
    args = request.form
    if '_method' in args:
        request.method = args['_method']
    if request.method == 'POST':
        pm.permit(args['token'])
        return "<html><head><meta http-equiv=refresh content=\"1; URL=/\"></head>\
                <body>Peer enabled</body></html>"
    if request.method == 'DELETE':
        pm.permit(args['token'], False)
        return "<html><head><meta http-equiv=refresh content=\"1; URL=/\"></head>\
                <body>Peer disabled</body></html>"

@app.route("/api/managepeer", methods=['GET', 'POST', 'DELETE'])
def apimanagepeer():
    args = request.form
    if '_method' in args:
        request.method = args['_method']
    if request.method == 'POST':
        pm.permit(args['token'], False)
        return "<html><head><meta http-equiv=refresh content=\"1; URL=/\"></head>\
                </head><body>Peer added</body></html>"
    if request.method == 'DELETE':
        pm.delete(args['token'])
        return "<html><head><meta http-equiv=refresh content=\"1; URL=/\"></head>\
                </head><body>Peer removed</body></html>"



@app.route("/api/connectpeer", methods=['POST', 'GET', 'DELETE'])
@auth.login_required
def apiconnect():
    #pubkey = request.args.get('pubkey', '')
    pubkey = request.json['pubkey']
    #try:
    if request.method == 'DELETE':
        vpn.deleteClient(pubkey)
        return json.dumps({'success': True})
    if request.method == 'POST':
        client = vpn.addClient(pubkey, auth.current_user())
        serverPubKey = vpn.getPubKey().decode()
        return json.dumps({'success': True, 'pubkey': serverPubKey, 'ip':
            client['ip'], 'iprng': vpn.getIPRng(), 'host': vpn.hostname})
    if request.method == 'GET':
        client = vpn.checkClient(pubkey, auth.current_user())
        serverPubKey = vpn.getPubKey().decode()
        return json.dumps({'success': True, 'pubkey': serverPubKey, 'ip':
            client['ip'], 'iprng': vpn.getIPRng(), 'host': vpn.hostname})

    #except Exception as e:
    #    raise(e)
    #    pass

    return json.dumps({'success': False})


@app.route("/")
def hello_world():
    page = "<html><head>"
    page += "<title>VPN Server Dashboard</title>"
    page += "<meta http-equiv=\"refresh\" content=\"1\" />"
    page += "</head><body>"


    page += "<table>"
    page += "<tr><th>token</th><th>peer</th><th>permitted</th></tr>"
    for k, v in pm.peers.items():
        page += "<tr><td>{}</td><td>{}</td><td>{}</td>".format(k, v['name'],
                v['permit'])
        page += "<td><form action=/api/permitpeer method=post> \
                   <input type=hidden id=token name=token value={}> \
                   <input type=submit value=enablepeer ></form></td>".format(k)
        page += "<td><form action=/api/permitpeer method=post> \
                   <input type=hidden name=_method value=DELETE> \
                   <input type=hidden id=token name=token value={}> \
                   <input type=submit value=disablepeer ></form></td>".format(k)
        page += "<td><form action=/api/managepeer method=post> \
                   <input type=hidden name=_method value=DELETE> \
                   <input type=hidden id=token name=token value={}> \
                   <input type=submit value=removepeer ></form></td>".format(k)
    page += "</table>"

    page += "<table>"
    page += "<tr><th>PUBKEY</th><td>{}</td>".format(vpn.getPubKey().decode())
    for k, v in vpn.getConfig().items():
        page += "<tr><th>{}</th><td>{}</td></tr>".format(k, v)
    page += "</table>"
    page += "<table>"
    page += "<tr><th>Peer public key</th><th>machine user</th><th>ip</th><th>created age (s)</th><th>renewed age (s)</th></tr>"
    t = time.time()
    for k, v in vpn.getClientDict().items():
        page += "<tr><td>{}</td><td>{}</td><td>{}</td><td align=right>{:9.1f}</td><td align=right>{:9.1f}</td></tr>".format(k, v['user'], v['ip'], t-v['created'], t-v['renewed'])
    page += "</table>"
    page += "</body></html>"
    return page





