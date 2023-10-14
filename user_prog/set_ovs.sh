#!/usr/bin/bash
set -e
agent_names=$(kubectl get pods -owide -n kube-system | grep antrea-agent | awk '{print $1}')
for agent_name in $agent_names
do
  cmd_prefix="kubectl exec -n kube-system $agent_name -c antrea-ovs -- "
  $cmd_prefix ovs-ofctl mod-flows br-int "table=ConntrackState, priority=190,ct_state=-new+trk,ip actions=load:1->nw_tos[3],resubmit(,AntreaPolicyEgressRule)"
  $cmd_prefix ovs-ofctl mod-flows br-int "table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ip actions=load:1->nw_tos[3],load:0x1->NXM_NX_REG0[9],resubmit(,AntreaPolicyEgressRule)"
  echo "On $agent_name:"
  $cmd_prefix ovs-ofctl dump-flows br-int table=ConntrackState
done
