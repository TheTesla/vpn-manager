#!/bin/bash

ip link add dev wg0 type wireguard

umask 077

wg genkey > privatekey

wg genpsk > psk

wg pubkey < privatekey > publickey


echo "pubkey ="
cat publickey

echo "psk ="
cat psk

sleep 5

export MYPUBKEY=$(cat publickey)

echo $MYPUBKEY

export APIRV=$(curl -X POST vpnserver:5000/api/connectpeer -H "Authorization: Bearer mytokenhome" -H "Content-Type: application/json" -d '{ "pubkey": "'$MYPUBKEY'"}')

export SERVPUBKEY=$(echo $APIRV | jq -r .pubkey)
export WGADR=$(echo $APIRV | jq -r .ip)


echo $SERVPUBKEY
echo $WGADR

ip address add dev wg0 $WGADR

wg set wg0 listen-port 51820 private-key privatekey 


wg set wg0 peer $SERVPUBKEY allowed-ips $WGADR endpoint $ENDPOINT

ip link set up dev wg0


echo "test"

while true
do
curl -X POST vpnserver:5000/api/connectpeer -H "Authorization: Bearer mytokenhome" -H "Content-Type: application/json" -d '{ "pubkey": "'$MYPUBKEY'"}'
sleep 5
done
