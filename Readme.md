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
docker run -d -p 6126:6126 kube-ncmp:latest
```

#### Run tool
```
python3 kube-ncmp.py --cache --namespace kube-system
```

##### Deploy as a helm chart

#### Update image and values needed in values.yaml
    .. code-block:: bash
      image:
        repository: new_kube_ncmp
        tag: latest
        pullPolicy: IfNotPresent

### After updating the Values.yaml deploy the application using

```
helm install --dry-run --debug ./prometheus-kube-network-metrics/
helm install --name prometheus-kube-network-metrics ./prometheus-kube-network-metrics --namespace=osh-infra
```

### Clean the setup using.
```
helm del --purge prometheus-kube-network-metrics
```
