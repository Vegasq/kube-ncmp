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

#### Update image in deployment.yaml or pod.yaml
    .. code-block:: bash
      containers:
      - name: prometheus-kube-network-metrics
        image: new_kube_ncmp
        imagePullPolicy: IfNotPresent

#### Push the kube-ncmp.py as a configmap in kubernetes.
```
kubectl create configmap prometheus-kube-network-metrics --from-file=ncmp=<filepath> -n <namespace>
```

#### Run ncmp on kubernetes.
```
kubectl apply -f serviceaccount.yaml
kubectl apply -f clusterrole.yaml
kubectl apply -f clusterolebinding.yaml
kubectl apply -f deployment.yaml (if you want to deploy application as a deployment)
kubectl apply -f pod.yaml (if you want to deploy application as a pod)
kubectl apply -f service.yaml (Expose your app)
```
