# kube-ncmp
## Tool to validate interconnection between containers in kubernetes cloud.
--

### About

Often problem withing big production clouds is accidental lost of connectivity between compute nodes.

`kube-ncmp` will connect to your pods and `ping` pods on other nodes.

### Usage

#### Deploying Kubernetes
```
docker build . -t kube-ncmp
```

#### Update image and values needed in values.yaml
    .. code-block:: bash
      image:
        repository: new_kube_ncmp
        tag: latest
        pullPolicy: IfNotPresent

### After updating the Values.yaml deploy the application using
```
cd ..
helm install --dry-run --debug ./prometheus-kube-network-metrics/
helm install --name prometheus-kube-network-metrics ./prometheus-kube-network-metrics --namespace=osh-infra
```

### Clean the setup using.
```
helm del --purge prometheus-kube-network-metrics
```
