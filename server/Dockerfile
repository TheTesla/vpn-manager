FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive 

RUN apt-get -y update && apt-get install -y wireguard iproute2 iptables python3 python3-pip

RUN apt-get -y update && apt-get install -y iputils-ping curl net-tools traceroute

RUN pip3 install flask flask_httpauth python-iptables pyroute2


COPY vpnconfig.py /.

COPY entrypoint.sh /.

RUN chmod +x entrypoint.sh

EXPOSE 5000

CMD ["/bin/bash", "-c", "/entrypoint.sh"]

