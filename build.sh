cp kube-ncmp.py prometheus-kube-network-metrics
helm install --name prometheus-kube-network-metrics ./prometheus-kube-network-metrics --namespace=osh-infra

