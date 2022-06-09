#!/bin/bash

ip link add dev wg0 type wireguard

ip address add dev wg0 $WGADR

umask 077

wg genkey > privatekey

wg genpsk > psk

wg pubkey < privatekey > publickey


echo "pubkey ="
cat publickey

echo "psk ="
cat psk

wg set wg0 listen-port 51820 private-key privatekey 

ip link set up dev wg0


echo "test"

export FLASK_APP=vpnconfig

flask run --host=0.0.0.0 > flask.log

