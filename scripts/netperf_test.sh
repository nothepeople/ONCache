cat > test_server.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-server
  labels:
    app: test-server
spec:
  containers:
  - name: test-server
    image: cilium/netperf
    imagePullPolicy: IfNotPresent
    command: ["sleep"]
    args: ["1000000"]
  restartPolicy: Never
  nodeName: node1
EOF

kubectl delete -f test_server.yaml
kubectl apply -f test_server.yaml

cat > test_client.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-client
  labels:
    app: test-client
spec:
  containers:
  - name: test-client
    image: cilium/netperf
    imagePullPolicy: IfNotPresent
    command: ["sleep"]
    args: ["1000000"]
  restartPolicy: Never
  nodeName: node2
EOF

kubectl delete -f test_client.yaml
kubectl apply -f test_client.yaml

sleep 5
set -x
kubectl get pods -owide
