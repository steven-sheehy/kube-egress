# Kubernetes Egress
Redirects all outgoing pod traffic via multiple static egress IPs. Normally egress traffic has its source IP translated (SNAT) to appear as the node IP when it leaves the cluster. This project will instead route outgoing pod traffic to the node that currently has the VIP and SNAT it to appear as the VIP. In some cloud providers, this functionality can be handled by a NAT gateway, but that is not feasible in a bare metal environment.

See discussion in [kube-router](https://github.com/cloudnativelabs/kube-router/issues/434) for additional detail.

## Use Case
A lot of external devices that pods connect have IP based ACLs to restrict incoming traffic for security reasons and bandwidth limitations. For example, routers and switches sometimes only allow a single IP to connect via SNMP to avoid a DDoS attack on critical network infrastructure. With multi-node Kubernetes cluster, the IP connecting to these devices could be any one of the nodes and would be changing as nodes come and go.

## Usage
View the egress command line arguments to see what options are available.

```shell
$ docker run -it --rm ssheehy/kube-egress --help
Redirects container traffic from all nodes to the node with the VIP

Usage:
  egress.sh [options]

Options:
  -d, --delete               Deletes all iptables and routing rules associated with the egress and exit
  -h, --help                 Displays the help text
  -i, --interface            The network interface to use. Default is eth0
  -p, --pod-subnet           The Kubernetes pod IP allocation range. Default is 10.32.0.0/12
  -r, --vip-routeid-mappings The directory that contains mappings from VIP to route ID. Default is /etc/kube-egress/vip_routeid_mapping/
  -s, --service-subnet       The Kubernetes service IP allocation range. Default is 10.96.0.0/12
  -u, --update-interval      How often to check to see if the rules need to be updated based upon VIP changes. Default is empty for run once
  -v, --podip-vip-mappings   The directory that contains mappings from Pod IP to VIP. Default is /etc/kube-egress/podip_vip_mapping/
```

Use either (1) or (2) below to manage mappings.

### (1) Manually configure pod ip and VIP mappings

Update the `podip_vip.yaml` and `vip_routeid.yaml` and create configMaps.
Note that `podip_vip.yaml` defines key-value pairs, where key is a PodIP and value is a VIP,
and `vip_routeid.yaml` defines key-value pairs, where key is VIP and value is route ID.
(Route ID can be any unique value for each vip between 1 and 252. See man ip for details on range of this value.)
Then, update the `daemonset.yaml` with the options required and run it.

```shell
kubectl apply -f daemonset.yaml
```

On pod ip changes, mappings needs to be changed manually by users.

### (2) Use operator to automatically update pod ip and VIP mappings

Use [egress-mapper](https://github.com/mkimuram/egress-mapper) operator to manage both kube-egress and keepalived-vip.
Then update vip cr and egress cr to mangage pod ip and VIP mappings.

On pod ip changes, the operator will automatically update mappings.

## Limitations
- No ability to restrict by namespace
- IP must already be routable to the nodes and appear as a virtual IP on exactly one of the nodes

## Build

```shell
docker build --pull -t ssheehy/kube-egress:latest .
docker push ssheehy/kube-egress
```

