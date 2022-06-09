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

sleep 3

export MYPUBKEY=$(cat publickey)

echo $MYPUBKEY

export SERVPUBKEY=$(curl -X POST vpnserver:5000/api/connectpeer?pubkey=$MYPUBKEY | jq -r .pubkey)

echo $SERVPUBKEY

wg set wg0 peer $SERVPUBKEY allowed-ips $WGADRRNG endpoint $ENDPOINT

ip link set up dev wg0


echo "test"


sleep 1000
