#!/usr/bin/env python3
from flask import Flask
from flask import request
from flask_httpauth import HTTPTokenAuth, HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash


import subprocess as sp
import json
import time
from threading import Thread



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


class UserManager:
    def __init__(self):
        self.users = {'admin': {
                        'password': generate_password_hash("sicher"),
                        'roles': ['admin', 'user'] } }

    def verify(self, username, password):
        if username not in self.users:
            return False
        if check_password_hash(self.users[username]['password'], password):
            return username
        return False

    def hasRole(self, username, role):
        if username not in self.users:
            return False
        if role in self.users[username]['roles']:
            return True
        return False


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


class DHCPv4:
    def __init__(self, timeout = 10):
        self.__IPs = dict()
        self.__timeout = timeout

    def addIPs(self, ip):
        if type(ip) is set:
            ip = list(ip)
        if type(ip) is list:
            return [self.addIPs(e) for e in ip]
        if ip in self.__IPs:
            return False
        self.__IPs[ip] = 0
        return True

    def getAllIPs(self):
        return set(self.__IPs.keys())

    def getAllAvailableIPs(self):
        now = time.time()
        return {k for k, v in self.__IPs.items() if v + self.__timeout < now}

    def offer(self):
        return list(self.getAllAvailableIPs())

    def renew(self, ip):
        if ip not in self.__IPs:
            return False
        if ip not in self.getAllAvailableIPs():
            self.__IPs[ip] = time.time()
            return True
        return False

    def request(self, ip):
        if ip not in self.__IPs:
            return False
        if ip in self.getAllAvailableIPs():
            self.__IPs[ip] = time.time()
            return True
        return False

    def release(self, ip):
        if ip not in self.__IPs:
            return False
        self.__IPs[ip] = 0
        return True

    def giveIP(self, currentIP=None):
        if not currentIP:
            ips = self.offer()
            if len(ips) == 0:
                return False
            ip = ips[0]
            self.request(ip)
            return ip
        if self.renew(currentIP):
            return currentIP
        return self.giveIP()

    def getAllUsed(self):
        now = time.time()
        return {k: v for k, v in self.__IPs.items() if v + self.__timeout > now}



class VPNManager:
    def __init__(self, ip='10.23.42.1/24', port=51820, dev='wg0',
            timeout=10, dhcpv4=None):
        self.__enabled = False
        self.__clientDict = {}
        self.__timeout = timeout
        self.__alive = True
        self.__thrd = Thread(target=self.purgeTimeoutThrdFunc)
        self.__thrd.start()
        self.setConfig(ip, port, dev, timeout)
        self.hostname = 'vpnserver'
        if dhcpv4 is None:
            dhcpv4 = DHCPv4()
        self.dhcpv4 = dhcpv4

    def setConfig(self, ip=None, port=None, dev=None, timeout=None):
        if ip is not None:
            self.__ip = ip
            self.__ipRng = calcIpNet(ip)
        if port is not None:
            self.__port = port
        if dev is not None:
            self.__dev = dev
        if timeout is not None:
            self.__timeout = timeout
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
                'dev': self.__dev, 'timeout': self.__timeout}

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
            #self.__ipSet.add(self.__clientDict[pubkey]['ip'])
            self.dhcpv4.release(self.__clientDict[pubkey]['ip'])
            del self.__clientDict[pubkey]
        run(['wg', 'set', self.__dev, 'peer', pubkey, 'remove'])

    def addClient(self, pubkey, user):
        if pubkey not in self.__clientDict:
            self.__clientDict[pubkey] = {}
            #self.__clientDict[pubkey]['ip'] = self.__ipSet.pop()
            self.__clientDict[pubkey]['ip'] = self.dhcpv4.giveIP()
            self.__clientDict[pubkey]['created'] = time.time()
            self.__clientDict[pubkey]['user'] = user
        self.__clientDict[pubkey]['ip'] = self.dhcpv4.giveIP(self.__clientDict[pubkey]['ip'])
        self.__clientDict[pubkey]['renewed'] = time.time()
        run(['wg', 'set', self.__dev, 'peer', pubkey, 'allowed-ips',
            self.__ipRng])
        return self.__clientDict[pubkey]


    def checkClient(self, pubkey, user):
        if pubkey not in self.__clientDict:
            return None
        self.__clientDict[pubkey]['ip'] = self.dhcpv4.giveIP(self.__clientDict[pubkey]['ip'])
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

#iptables -A FORWARD -i eth0 -o wg0 -p tcp --syn --dport 80 -m conntrack --ctstate NEW -j ACCEPT
#iptables -A FORWARD -i eth0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#iptables -A FORWARD -i wg0 -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.23.42.32
#iptables -t nat -A POSTROUTING -o wg0 -p tcp --dport 80 -d 10.23.42.32 -j SNAT --to-source 10.23.42.1




app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')
authuser = HTTPBasicAuth()


dhcpv4 = DHCPv4()
dhcpv4.addIPs(ipRng2set('10.23.42.2','10.23.42.150','10.23.42.1/24'))

vpn = VPNManager(dhcpv4=dhcpv4)
vpn.enable()


pm = PeerManager()

um = UserManager()


@authuser.verify_password
def verify_password(username, password):
    return um.verify(username, password)

@auth.verify_token
def verify_token(token):
    return pm.verify(token)

@app.route("/api/permitpeer", methods=['GET', 'POST', 'DELETE'])
@authuser.login_required
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
@authuser.login_required
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
    pubkey = request.json['pubkey']
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
    return json.dumps({'success': False})


@app.route("/")
@authuser.login_required
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
    page += "DHCP v4"
    page += "<table>"
    page += "<tr><th>ip</th><th>age</th></tr>"

    for k, v in dhcpv4.getAllUsed().items():
        now = time.time()
        page += "<tr><td>{}</td><td>{}</td></tr>".format(k, now-v)
    page += "</table>"
    page += "<table>"
    page += "<tr><th>Peer public key</th><th>machine user</th><th>ip</th><th>created age (s)</th><th>renewed age (s)</th></tr>"
    #page += "<tr><th>Peer public key</th><th>ip</th><th>created age (s)</th><th>renewed age (s)</th></tr>"
    t = time.time()
    for k, v in vpn.getClientDict().items():
        page += "<tr><td>{}</td><td>{}</td><td>{}</td><td align=right>{:9.1f}</td><td align=right>{:9.1f}</td></tr>".format(k, v['user'], v['ip'], t-v['created'], t-v['renewed'])
        #page += "<tr><td>{}</td><td>{}</td><td>{}</td><td align=right>{:9.1f}</td><td align=right>{:9.1f}</td></tr>".format(k, v['ip'], t-v['created'], t-v['renewed'])
    page += "</table>"
    page += "</body></html>"
    return page





