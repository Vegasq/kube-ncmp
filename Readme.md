# kube-ncmp
## Tool to validate interconnection between containers in kubernetes cloud.
--

Integrated as part of: ()[https://review.openstack.org/#/c/642791/]

### About

Often problem withing big production clouds is accidental lost of connectivity between compute nodes.

`kube-ncmp` will connect to your pods and `ping` pods on other nodes.

### Usage

#### Run tool
```
python3 kube_ncmp.py --cache --namespace kube-system
```
