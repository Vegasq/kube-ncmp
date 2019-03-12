FROM docker.io/ubuntu:xenial
MAINTAINER vegasq@gmail.com

RUN apt-get update ;\
    apt-get upgrade -y gcc;\
    apt-get install -y --no-install-recommends python-pip \
    python-setuptools python3-pip python3-dev \
    apt-transport-https curl

RUN curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
RUN echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" | tee -a /etc/apt/sources.list.d/kubernetes.list
RUN apt-get update
RUN apt-get install -y kubectl
RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install ipaddress setuptools kubernetes prometheus-client

