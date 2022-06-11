from flask import Flask
from flask import request
import subprocess as sp
import json
import time
from threading import Thread


#ip = '10.23.42.2/24'
#
#ipadrrng = "10.23.42.0/24"
#
#ipSet = {'10.23.42.2/24', '10.23.42.3/24', '10.23.42.4/24', '10.23.42.5/24'}
#
#clientDict = {}


def run(cli):
    sp.check_output(cli)

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
    print(m)
    print(h)
    print(s)
    print(e)
    if s > e:
        raise ValueError('IP range end before start')
    if (s & m) != (h & m):
        raise ValueError('IP range start violates netmask')
    if (e & m) != (h & m):
        raise ValueError('IP range end violates netmask')
    return {value2ip(x)+'/{}'.format(ms) for x in range(s,e)}



class VPNManager:
    def __init__(self, ip='10.23.42.1/24', port=51820, dev='wg0',
            dhcpStart='10.23.42.2', dhcpEnd='10.23.42.150', timeout=10):
        self.__enabled = False
        self.setConfig(ip, port, dev, dhcpStart, dhcpEnd, timeout)

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
#        self.__thrd = Thread(target=self.purgeTimeout, args=(self))
#        self.__thrd.start()
        self.__setupLink()

    def disable(self):
        self.__enabled = False
        self.__setupLink()


    def getIPRng(self):
        return self.__ipRng

    def getClientDict(self):
        return self.__clientDict

    def __setupLink(self):
        self.__rmLink()
        if self.__enabled == False:
            return
        run(['ip', 'link', 'add', 'dev', self.__dev, 'type', 'wireguard'])
        run(['ip', 'address', 'add', 'dev', self.__dev, self.__ip])
        run(['wg', 'set', self.__dev, 'listen-port', str(self.__port), 'private-key',
        'privatekey'])
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

    def addClient(self, pubkey):
        if pubkey not in self.__clientDict:
            self.__clientDict[pubkey] = {}
            self.__clientDict[pubkey]['ip'] = self.__ipSet.pop()
        self.__clientDict[pubkey]['timestamp'] = time.time()
        run(['wg', 'set', self.__dev, 'peer', pubkey, 'allowed-ips',
            self.__ipRng])
        return self.__clientDict[pubkey]


    def checkClient(self, pubkey):
        if pubkey not in self.__clientDict:
            return None
        self.__clientDict[pubkey]['timestamp'] = time.time()
        return self.__clientDict[pubkey]

    def purgeTimeout(self):
        t = time.time()
        for k, v in self.__clientDict.items():
            age = t-v['timestamp']
            if age > self.__timeout:
                self.__deleteClient(k)

    def purgeTimeoutThrdFunc(self):
        while(self.__enabled):
            time.sleep(1)
            self.purgeTimeout()

    def __del__(self):
        self.disable()


#def deleteClient(pubkey):
#    if pubkey in clientDict:
#        ipSet.add(clientDict[pubkey]['ip'])
#        del clientDict[pubkey]
#    sp.check_output(['wg', 'set', 'wg0', 'peer', pubkey, 'remove'])
#
#def addClient(pubkey):
#    if pubkey not in clientDict:
#        clientDict[pubkey] = {}
#        clientDict[pubkey]['ip'] = ipSet.pop()
#    clientDict[pubkey]['timestamp'] = time.time()
#    sp.check_output(['wg', 'set', 'wg0', 'peer', pubkey, 'allowed-ips',
#        ipadrrng])
#    return clientDict[pubkey]
#
#def checkClient(pubkey):
#    if pubkey not in clientDict:
#        return None
#    clientDict[pubkey]['timestamp'] = time.time()
#    return clientDict[pubkey]
#
#def purgeTimeout():
#    t = time.time()
#    for k, v in clientDict.items():
#        age = t-v['timestamp']
#        if age > 10:
#            deleteClient(k)
#
#def purgeTimeoutThrdFunc():
#    while(True):
#        time.sleep(1)
#        purgeTimeout()
#
#
#thrd = Thread(target=purgeTimeoutThrdFunc)
#thrd.start()

app = Flask(__name__)


vpn = VPNManager()
vpn.enable()


@app.route("/api/connectpeer", methods=['POST', 'GET', 'DELETE'])
def apiconnect():
    #pubkey = request.args.get('pubkey', '')
    pubkey = request.json['pubkey']
    try:
        if request.method == 'DELETE':
            vpn.deleteClient(pubkey)
            return json.dumps({'success': True})
        if request.method == 'POST':
            client = vpn.addClient(pubkey)
            with open("publickey", 'r') as f:
                clientPubKey = f.read()
            return json.dumps({'success': True, 'pubkey': clientPubKey, 'ip':
                client['ip'], 'iprng': vpn.getIPRng()})
        if request.method == 'GET':
            client = checkClient(pubkey)
            return json.dumps({'success': True, 'pubkey': clientPubKey, 'ip':
                client['ip'], 'iprng': ipadrrng})

    except Exception as e:
        assert(e)
        pass

    return json.dumps({'success': False})


@app.route("/")
def hello_world():
    page = "<html><head>"
    page += "<title>VPN Server Dashboard</title>"
    page += "<meta http-equiv=\"refresh\" content=\"1\" />"
    page += "</head><body>"
    page += "<table>"
    page += "<tr><th>Peer public key</th><th>ip</th><th>renewal age (s)</th></tr>"
    t = time.time()
    for k, v in vpn.getClientDict().items():
        page += "<tr><td>{}</td><td>{}</td><td align=right>{:9.1f}</td></tr>".format(k, v['ip'],
                t-v['timestamp'])
    page += "</table>"
    page += "</body></html>"
    return page

