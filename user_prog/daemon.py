import time
import subprocess
import yaml
import atexit

NODE_IFNAME = "ens1f0np0"
POD_IFNAME = "eth0"

configed_pod = []

def runcmd(cmd):
    return subprocess.check_output(cmd, shell=True).decode().strip()

# For kubernetes case. Will only check the pods in the default namespace.
def pod_watcher():
    print("Watching Pods...")
    crictl = "crictl --runtime-endpoint unix:///run/containerd/containerd.sock "
    while True:
        namelist = runcmd("kubectl get pods -o wide 2>&1 | grep Running " + r" | awk -F ' ' '{print $1}'").split()
        podsyaml = {}
        podsyaml["ingress_cache"] = {}
        map_add = False
        for podname in namelist:
            cid = runcmd(crictl + f" ps | grep {podname}" + r"| awk '{print $1}'")
            if (not cid) or (cid in configed_pod):
                continue
            map_add = True
            configed_pod.append(cid)
            # Get info of the pod
            cmd = crictl + r" inspect --template '{{.info.pid}}' --output go-template " + cid
            pid = runcmd(cmd)
            net_info_folder = "/sys/class/net/"
            cmd_prefix = crictl + f" exec -it {cid} "
            pod_peer_ifidx = int(runcmd(cmd_prefix + f"cat {net_info_folder}{POD_IFNAME}/iflink"))
            pod_peer_ifname = runcmd(f"ip link show | grep '{pod_peer_ifidx}:' -w " + r"| awk -F '@' '{{printf $1}}' | awk '{{printf $2}}'")
            podip = runcmd(f"kubectl get pods {podname} -o custom-columns=IP:.status.podIP --no-headers=true")
            # Generate map yaml
            tmp_dict = {}
            tmp_dict["ifidx"] = pod_peer_ifidx
            podsyaml["ingress_cache"][podip] = tmp_dict

            # Load tc_init_in
            cmd_prefix=f"nsenter -t {pid} -n "
            runcmd(cmd_prefix + f"./tc_prog_loader --dev {POD_IFNAME} --filename ../tc_prog/tc_prog_kern.o --sec-name tc_init_in --new-qdisc")
            # Load tc_masq
            runcmd(f"./tc_prog_loader --dev {pod_peer_ifname} --filename ../tc_prog/tc_prog_kern.o --sec-name tc_masq --new-qdisc")
            print("Configed a new Pod!")

        if map_add == True:
            with open("./mapdata.yaml", 'w') as f:
                yaml.dump(podsyaml, f, default_flow_style=False)
            out = runcmd("./set_map")
            print("Added some Podinfo to the eBPF map")
        time.sleep(1)

def init_daemon():
    configed_pod.extend(runcmd("crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps | awk '{print $1}' | sed 1d").split())

    runcmd("rm -rf /sys/fs/bpf/tc/globals/*")
    runcmd(f"./tc_prog_loader --dev {NODE_IFNAME} --filename ../tc_prog/tc_prog_kern.o --sec-name tc_init_e --egress --new-qdisc")
    runcmd(f"./tc_prog_loader --dev {NODE_IFNAME} --filename ../tc_prog/tc_prog_kern.o --sec-name tc_restore")
    nodeyaml = {}
    nodeyaml["devmap"] = {}
    net_info_folder = "/sys/class/net/"
    ifidx = int(runcmd(f"cat {net_info_folder}{NODE_IFNAME}/ifindex"))
    ifmac = runcmd(f"cat {net_info_folder}{NODE_IFNAME}/address")
    ifip = runcmd(f"ip addr show {NODE_IFNAME} | grep 'inet ' | awk '{{print $2}}' | awk -F '/' '{{print $1}}'")
    tmpdict = {"ip": ifip, "mac": ifmac}
    nodeyaml["devmap"][ifidx] = tmpdict
    with open("./mapdata.yaml", 'w') as f:
        yaml.dump(nodeyaml, f, default_flow_style=False)
    runcmd("./set_map")
    out = runcmd("bash set_ovs.sh")
    print(out)

@atexit.register
def cleanup():
    runcmd("rm -rf /sys/fs/bpf/tc/globals/*")
    runcmd(f"./tc_prog_loader --dev {NODE_IFNAME} --remove --egress")
    runcmd(f"./tc_prog_loader --dev {NODE_IFNAME} --remove")
    print("Cleanup finished")

if __name__ == '__main__':
    init_daemon()
    print("init daemon finished")
    pod_watcher()
