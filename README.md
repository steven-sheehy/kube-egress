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
  -r, --vip-routeid-mappings The directory that contains mappings from VIP to route ID. Default is config/vip_routeid_mapping/
  -s, --service-subnet       The Kubernetes service IP allocation range. Default is 10.96.0.0/12
  -u, --update-interval      How often to check to see if the rules need to be updated based upon VIP changes. Default is empty for run once
  -v, --podip-vip-mappings   The directory that contains mappings from Pod IP to VIP. Default is config/podip_vip_mapping/
```

Update the `podip_vip.yaml` and `vip_routeid.yaml` and create configMaps.
Note that `podip_vip.yaml` defines key-value pairs, where key is a PodIP and value is a VIP,
and `vip_routeid.yaml` defines key-value pairs, where key is VIP and value is route ID.
Then, update the `daemonset.yaml` with the options required and run it.

```shell
kubectl apply -f daemonset.yaml
```

## Limitations
- No ability to restrict by namespace
- IP must already be routable to the nodes and appear as a virtual IP on exactly one of the nodes

## Build

```shell
docker build --pull -t ssheehy/kube-egress:latest .
docker push ssheehy/kube-egress
```

