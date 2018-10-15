# Kubernetes Egress
Redirects all outgoing pod traffic via a single static egress IP. Normally egress traffic has its source IP translated (SNAT) to appear as the node IP when it leaves the cluster. This project will instead route outgoing pod traffic to the node that currently has the VIP and SNAT it to appear as the VIP. In some cloud providers, this functionality can be handled by a NAT gateway, but that is not feasible in a bare metal environment.

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
  -d, --delete               Deletes all iptables and routing rules associated with the egress
  -h, --help                 Displays the help text
  -i, --interface            The network interface to use. Default is eth0
  -p, --pod-subnet           The Kubernetes pod IP allocation range. Default is 10.32.0.0/12
  -r, --route-id             The route ID to use for the routing table and to mark traffic. Default is 64
  -s, --service-subnet       The Kubernetes service IP allocation range. Default is 10.96.0.0/12
  -u, --update-interval      How often to check to see if the rules need to be updated based upon VIP changes. Default is empty for run once
  -v, --vip                  The egress IP to route traffic to
```

Update the `daemonset.yaml` with the options required and run it. At minimum, you will need to supply the VIP using the `--vip` flag.

```shell
kubectl apply -f daemonset.yaml
```

## Limitations
- Only supports a single egress IP
- No ability to redirect only a subset of pods/services
- No ability to restrict by namespace
- IP must already be routable to the nodes and appear as a virtual IP on exactly one of the nodes

## Build

```shell
docker build --pull -t ssheehy/kube-egress:latest .
docker push ssheehy/kube-egress
```

