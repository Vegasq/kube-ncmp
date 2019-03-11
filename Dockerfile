FROM docker.io/ubuntu:xenial
MAINTAINER vegasq@gmail.com

RUN apt-get update ;\
    apt-get upgrade -y gcc;\
    apt-get install -y --no-install-recommends python-pip \
    python-setuptools python3-pip python3-dev

RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install ipaddress setuptools kubernetes prometheus-client
