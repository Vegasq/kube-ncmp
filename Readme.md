# kube-ncmp
## Tool to validate interconnection between containers in kubernetes cloud.
--

### About

Often problem withing big production clouds is accidental lost of connectivity between compute nodes.

`kube-ncmp` will connect to your pods and `ping` pods on other nodes.

### Usage

```
python kube-ncmp.py --cache --namespace kube-system
```
