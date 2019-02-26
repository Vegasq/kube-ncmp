FROM docker.io/ubuntu:xenial
MAINTAINER vegasq@gmail.com

RUN mkdir /root/.kube
COPY .kube /root/.kube

RUN mkdir /app
COPY . /app

RUN apt-get update ;\
    apt-get upgrade -y gcc;\
    apt-get install -y --no-install-recommends python-pip python-setuptools python3-pip python3-dev

RUN pip3 install --upgrade pip
#Verify if we need this setuptools.
RUN pip3 install setuptools
RUN pip3 install -r /app/requirements.txt

ENTRYPOINT ["python3", "/app/kube-ncmp.py", "--namespace", "kube-system", "--port", "6126"]
