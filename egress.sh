#!/usr/bin/env bash
#
# Debugging:
# sudo iptables -nvL -t mangle
# sudo iptables -t raw -I PREROUTING -j TRACE
# sudo iptables -t mangle -A EGRESS -j LOG --log-prefix "egress: " --log-level 4
# sudo tail -f /var/log/syslog | grep "egress: "

set -e

# Parse Options
NAME=$(basename $0 | tr - ' ')
OPTS=$(getopt --options dhi:p:r:s:u:v: --longoptions delete,help,interface:,pod-subnet:,route-id:,service-subnet:,update-interval:,vip: --name "$NAME" -- "$@")
[[ $? != 0 ]] && echo "Failed parsing options" >&2 && exit 1
eval set -- "$OPTS"

# Variables
EGRESS=
INTERFACE="eth0"
ROUTE_ID="64"
ROUTE_TABLE="egress"
POD_SUBNET="10.32.0.0/12"
SERVICE_SUBNET="10.96.0.0/12"
UPDATE_INTERVAL=
VIP=""
VIP_EXISTS=false

# Functions
function help() {
  cat << EOF
Redirects container traffic from all nodes to the node with the VIP

Usage:
  $NAME [options]

Options:
  -d, --delete               Deletes all iptables and routing rules associated with the egress
  -h, --help                 Displays the help text
  -i, --interface            The network interface to use. Default is ${INTERFACE}
  -p, --pod-subnet           The Kubernetes pod IP allocation range. Default is ${POD_SUBNET}
  -r, --route-id             The route ID to use for the routing table and to mark traffic. Default is ${ROUTE_ID}
  -s, --service-subnet       The Kubernetes service IP allocation range. Default is ${SERVICE_SUBNET}
  -u, --update-interval      How often to check to see if the rules need to be updated based upon VIP changes. Default is empty for run once
  -v, --vip                  The egress IP to route traffic to
EOF
}

function add_iptables() {
  echo "Adding iptables rules"
  iptables -t mangle -N EGRESS
  iptables -t mangle -A EGRESS -d "${POD_SUBNET}" -j RETURN
  iptables -t mangle -A EGRESS -d "${SERVICE_SUBNET}" -j RETURN
  iptables -t mangle -A EGRESS -s "${POD_SUBNET}" -j MARK --set-mark "${ROUTE_ID}/${ROUTE_ID}"
  iptables -t mangle -A PREROUTING -j EGRESS
}

function add_egress() {
  echo "Adding iptables rules for egress"
  iptables -t mangle -A FORWARD -i "${INTERFACE}" -o "${INTERFACE}" -j MARK --set-mark "${ROUTE_ID}/${ROUTE_ID}"
  iptables -t nat -I POSTROUTING -o "${INTERFACE}" -m mark --mark "${ROUTE_ID}" -j SNAT --to "${VIP}"
}

function add_routes() {
  echo "Adding routing rules"
  echo "${ROUTE_ID} ${ROUTE_TABLE}" > "/etc/iproute2/rt_tables.d/${ROUTE_TABLE}.conf"
  ip route add default via "${VIP}" dev "${INTERFACE}" table "${ROUTE_TABLE}"
  ip rule add fwmark "${ROUTE_ID}" table "${ROUTE_TABLE}"
  ip route flush cache
}

function delete() {
  echo "Deleting iptables rules"
  iptables -t mangle -D PREROUTING -j EGRESS 2>/dev/null || true
  iptables -t mangle -D FORWARD -i "${INTERFACE}" -o "${INTERFACE}" -j MARK --set-mark "${ROUTE_ID}/${ROUTE_ID}" 2>/dev/null || true
  iptables -t mangle -F EGRESS 2>/dev/null || true
  iptables -t mangle -X EGRESS 2>/dev/null || true
  iptables -t nat -D POSTROUTING -o "${INTERFACE}" -m mark --mark "${ROUTE_ID}" -j SNAT --to "${VIP}" 2>/dev/null || true

  echo "Deleting routing rules"
  ip rule del table "${ROUTE_TABLE}" 2>/dev/null || true
  ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
  ip route flush cache
  rm -f "/etc/iproute2/rt_tables.d/${ROUTE_TABLE}.conf"
  EGRESS=
}

function apply() {
  VIP_EXISTS=false

  if (ip -o addr show "${INTERFACE}" | grep -Fq "${VIP}/32"); then
    VIP_EXISTS=true
  fi

  if [[ "${VIP_EXISTS}" == true && "${EGRESS}" != true ]]; then
    echo "VIP ${VIP} transitioned to primary"
    delete
    add_iptables
    add_egress
    EGRESS=true
    echo "Egress now enabled on node ${HOSTNAME}"
  fi

  if [[ "${VIP_EXISTS}" == false && "${EGRESS}" != false ]]; then
    echo "VIP ${VIP} transitioned to secondary"
    delete
    add_routes
    add_iptables
    EGRESS=false
    echo "Egress now disabled on node ${HOSTNAME}"
  fi
}

while true
do
  case "$1" in
    -d | --delete)
      delete
      exit 0
      ;;
    -h | --help)
      help
      exit 0
      ;;
    -i | --interface)
      INTERFACE="$2"
      shift 2
      ;;
    -p | --pod-subnet)
      POD_SUBNET="$2"
      shift 2
      ;;
    -r | --route-id)
      ROUTE_ID="$2"
      shift 2
      ;;
    -s | --service-subnet)
      SERVICE_SUBNET="$2"
      shift 2
      ;;
    -u | --update-interval)
      UPDATE_INTERVAL="$2"
      shift 2
      ;;
    -v | --vip)
      VIP="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
  esac
done

if [[ -z "${VIP}" ]]; then
  echo "Missing required --vip argument" >&2
  help
  exit 1
fi

# Verify interface exists
ip addr show "${INTERFACE}" >/dev/null

apply

while [[ -n "${UPDATE_INTERVAL}" ]]; do
  sleep "${UPDATE_INTERVAL}"
  apply
done

exit 0

