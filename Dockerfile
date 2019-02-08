FROM docker.io/ubuntu:xenial
MAINTAINER vegasq@gmail.com

RUN mkdir /app
COPY . /app

COPY .kube /root

RUN apt-get update ;\
    apt-get upgrade -y ;\
    apt-get install -y --no-install-recommends python-pip python-setuptools
RUN pip install --upgrade pip
RUN pip install -r /app/requirements.txt

ENTRYPOINT ["python", "/app/kube-ncmp.py", "--namespace", "kube-system", "--port", "6126"]
