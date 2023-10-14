set -x
set -e

LOCAL_ADDR=
REMOTE_ADDR=
USER_NAME=
ID_RSA_PATH=
# If no id_rsa, leave this variable empty
ID_RSA=" -i $ID_RSA_PATH "
# username@ip
REMOTEINFO="$USER_NAME@$REMOTE_ADDR"
POD_NET_CIDR=10.10.0.0/16

sudo swapoff -a
sudo rm -f /etc/containerd/config.toml; sudo systemctl restart containerd.service
echo "KUBELET_EXTRA_ARGS=--node-ip=$LOCAL_ADDR" | sudo tee /etc/default/kubelet
sudo systemctl restart kubelet.service
sudo kubeadm reset -f; rm $HOME/.kube/config -f
sudo kubeadm init --apiserver-advertise-address $LOCAL_ADDR \
            --pod-network-cidr $POD_NET_CIDR --node-name node1

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

JOIN_CMD="$(kubeadm token create --print-join-command) --node-name node2"

ssh -o "StrictHostKeyChecking=no" $ID_RSA $REMOTEINFO "sudo swapoff -a; sudo rm -f /etc/containerd/config.toml; sudo systemctl restart containerd.service"
ssh -o "StrictHostKeyChecking=no" $ID_RSA $REMOTEINFO "echo KUBELET_EXTRA_ARGS=--node-ip=$REMOTE_ADDR | sudo tee /etc/default/kubelet; sudo systemctl restart kubelet.service"
ssh -o "StrictHostKeyChecking=no" $ID_RSA $REMOTEINFO "sudo kubeadm reset -f; rm $HOME/.kube/config -f"
ssh -o "StrictHostKeyChecking=no" $ID_RSA $REMOTEINFO "sudo $JOIN_CMD; mkdir -p $HOME/.kube"
scp -o "StrictHostKeyChecking=no" $ID_RSA $HOME/.kube/config  $REMOTEINFO:$HOME/.kube/config

kubectl taint nodes node1 node-role.kubernetes.io/master- | true
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/v1.10.0/antrea.yml