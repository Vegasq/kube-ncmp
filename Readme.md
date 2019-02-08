# kube-ncmp
## Tool to validate interconnection between containers in kubernetes cloud.
--

### About

Often problem withing big production clouds is accidental lost of connectivity between compute nodes.

`kube-ncmp` will connect to your pods and `ping` pods on other nodes.

### Usage

#### Build container
```
docker build . -t kube-ncmp
```

#### Run container
```
docker run -p 6126:6126 kube-ncmp:latest
```

#### Run tool
```
python kube-ncmp.py --cache --namespace kube-system
```
