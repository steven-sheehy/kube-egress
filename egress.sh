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
OPTS=$(getopt --options dhi:p:r:s:u:v: --longoptions delete,help,interface:,pod-subnet:,vip-routeid-mappings:,service-subnet:,update-interval:,podip-vip-mappings: --name "$NAME" -- "$@")
[[ $? != 0 ]] && echo "Failed parsing options" >&2 && exit 1
eval set -- "$OPTS"

# Constants
ROUTE_ID_MASK=255
ROUTE_TABLE_PREFIX="egress"

# Variables
INTERFACE="eth0"
POD_SUBNET="10.32.0.0/12"
SERVICE_SUBNET="10.96.0.0/12"
PODIP_VIP_MAPPING_DIR="config/podip_vip_mapping/"
VIP_ROUTEID_MAPPING_DIR="config/vip_routeid_mapping/"
UPDATE_INTERVAL=
DELETE=false

# Functions
function help() {
  cat << EOF
Redirects container traffic from all nodes to the node with the VIP

Usage:
  $NAME [options]

Options:
  -d, --delete               Deletes all iptables and routing rules associated with the egress and exit
  -h, --help                 Displays the help text
  -i, --interface            The network interface to use. Default is ${INTERFACE}
  -p, --pod-subnet           The Kubernetes pod IP allocation range. Default is ${POD_SUBNET}
  -r, --vip-routeid-mappings The directory that contains mappings from VIP to route ID. Default is ${VIP_ROUTEID_MAPPING_DIR}
  -s, --service-subnet       The Kubernetes service IP allocation range. Default is ${SERVICE_SUBNET}
  -u, --update-interval      How often to check to see if the rules need to be updated based upon VIP changes. Default is empty for run once
  -v, --podip-vip-mappings   The directory that contains mappings from Pod IP to VIP. Default is ${PODIP_VIP_MAPPING_DIR}
EOF
}

function reload_mappings() {
  while read config;do
    PODIP_VIP_MAPPINGS["${config}"]=$(cat "${PODIP_VIP_MAPPING_DIR}/${config}")
  done <<< "$(ls ${PODIP_VIP_MAPPING_DIR})"

  while read config;do
    VIP_ROUTEID_MAPPINGS["${config}"]=$(cat "${VIP_ROUTEID_MAPPING_DIR}/${config}")
  done <<< "$(ls ${VIP_ROUTEID_MAPPING_DIR})"
}

function log() {
  local message="${1}"
  local timestamp=$(date -Iseconds)
  echo "${timestamp} ${message}"
}

function handle_chain() {
  local table_opt=${1}
  local table=${2}
  local action=${3}
  local chain=${4}

  if (iptables -t ${table} -nL ${chain} >/dev/null 2>&1);then
    # Delete or flash chain only when there's existing chain
    if [ ${action} == "-X" ] || [ ${action} == "-F" ];then
      iptables -t ${table} ${action} ${chain} 2>/dev/null || true
    fi
  else
    # Create chain only when there's no existing chain
    if [ ${action} == "-N" ];then
      iptables -t ${table} ${action} ${chain} 2>/dev/null || true
    fi
  fi
}

function handle_rule() {
  local table_opt=${1}
  local table=${2}
  local action=${3}
  local chain=${4}
  shift 4

  if (iptables -t ${table} -C ${chain} $@ 2>/dev/null);then
    # Delete rule only when there's existing rule
    if [ ${action} == "-D" ];then
      iptables -t ${table} ${action} ${chain} $@ 2>/dev/null || true
    fi
  else
    # Add or insert rule only when there's no existing rule
    if [ ${action} == "-A" ] || [ ${action} == "-I" ];then
      iptables -t ${table} ${action} ${chain} $@ 2>/dev/null || true
    fi
  fi
}

function apply() {
  unset PODIP_VIP_MAPPINGS
  unset VIP_ROUTEID_MAPPINGS
  declare -A PODIP_VIP_MAPPINGS
  declare -A VIP_ROUTEID_MAPPINGS
  reload_mappings

  log "Applying common iptables rules"
  handle_chain -t mangle -N EGRESS
  handle_rule -t mangle -A EGRESS -d "${POD_SUBNET}" -j RETURN
  handle_rule -t mangle -A EGRESS -d "${SERVICE_SUBNET}" -j RETURN
  handle_rule -t mangle -A PREROUTING -j EGRESS

  unset configured_vips
  declare -A configured_vips

  for POD_IP in "${!PODIP_VIP_MAPPINGS[@]}"; do
    VIP="${PODIP_VIP_MAPPINGS[$POD_IP]}"
    ROUTE_ID="${VIP_ROUTEID_MAPPINGS[$VIP]}"
    ROUTE_TABLE="${ROUTE_TABLE_PREFIX}_${ROUTE_ID}"

    handle_rule -t mangle -A EGRESS -s "${POD_IP}" -j MARK --set-mark "${ROUTE_ID}"

    if (ip -o addr show "${INTERFACE}" | grep -Fq "${VIP}"); then
      log "VIP ${VIP} for ${POD_IP} transitioned to primary"
	  # Add rules for primary
      handle_rule -t mangle -A FORWARD -s "${POD_IP}" -i "${INTERFACE}" -o "${INTERFACE}" -j MARK --set-mark "${ROUTE_ID}"
      handle_rule -t nat -I POSTROUTING -o "${INTERFACE}" -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j SNAT --to "${VIP}"
	  # Delete rules for secondory
      if [[ -z "${configured_vips[$VIP]+unset}" ]]; then
        log "VIP ${VIP} transitioned to secondary"
        handle_rule -t nat -D POSTROUTING -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j RETURN
        ip rule del table "${ROUTE_TABLE}" 2>/dev/null || true
        ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
        rm -f "/etc/iproute2/rt_tables.d/${ROUTE_TABLE}.conf"
        configured_vips["${VIP}"]=true
      fi
    else
	  # Add rules for secondary
      if [[ -z "${configured_vips[$VIP]+unset}" ]]; then
        log "VIP ${VIP} transitioned to secondary"
        handle_rule -t nat -I POSTROUTING -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j RETURN
        echo "${ROUTE_ID} ${ROUTE_TABLE}" > "/etc/iproute2/rt_tables.d/${ROUTE_TABLE}.conf"
		if ! (ip route show table ${ROUTE_ID} | grep -Fq "${VIP}"); then
          ip route add default via "${VIP}" dev "${INTERFACE}" table "${ROUTE_TABLE}"
		fi
		if ! (ip rule show | grep -Fq "${ROUTE_TABLE}"); then
          ip rule add fwmark "${ROUTE_ID}" table "${ROUTE_TABLE}"
		fi
        configured_vips["${VIP}"]=true
      fi
	  # Delete rules for primary
      handle_rule -t mangle -D FORWARD -s "${POD_IP}" -i "${INTERFACE}" -o "${INTERFACE}" -j MARK --set-mark "${ROUTE_ID}"
      handle_rule -t nat -D POSTROUTING -o "${INTERFACE}" -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j SNAT --to "${VIP}"
    fi
  done

  ip route flush cache
}

function delete() {
  unset PODIP_VIP_MAPPINGS
  unset VIP_ROUTEID_MAPPINGS
  declare -A PODIP_VIP_MAPPINGS
  declare -A VIP_ROUTEID_MAPPINGS
  reload_mappings

  for POD_IP in "${!PODIP_VIP_MAPPINGS[@]}"; do
    VIP="${PODIP_VIP_MAPPINGS[$POD_IP]}"
    ROUTE_ID="${VIP_ROUTEID_MAPPINGS[$VIP]}"
    ROUTE_TABLE="${ROUTE_TABLE_PREFIX}_${ROUTE_ID}"

    log "Deleting rule for VIP ${VIP} for ${POD_IP}"
    handle_rule -t mangle -D EGRESS -s "${POD_IP}" -j MARK --set-mark "${ROUTE_ID}"
    handle_rule -t mangle -D FORWARD -s "${POD_IP}" -i "${INTERFACE}" -o "${INTERFACE}" -j MARK --set-mark "${ROUTE_ID}"
    handle_rule -t nat -D POSTROUTING -o "${INTERFACE}" -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j SNAT --to "${VIP}"

    ip rule del table "${ROUTE_TABLE}" 2>/dev/null || true
    ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
    rm -f "/etc/iproute2/rt_tables.d/${ROUTE_TABLE}.conf"
    handle_rule -t nat -D POSTROUTING -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j RETURN
  done

  ip route flush cache

  log "Deleting common iptables rules"
  handle_rule -t mangle -D PREROUTING -j EGRESS
  handle_rule -t mangle -D EGRESS -d "${POD_SUBNET}" -j RETURN
  handle_rule -t mangle -D EGRESS -d "${SERVICE_SUBNET}" -j RETURN
  handle_chain -t mangle -F EGRESS
  handle_chain -t mangle -X EGRESS
}

while true
do
  case "$1" in
    -d | --delete)
      DELETE=true
      shift
      ;;
    -h | --help)
      help
      exit 0
      ;;
    -i | --interface)
      INTERFACE="${2:-$INTERFACE}"
      shift 2
      ;;
    -p | --pod-subnet)
      POD_SUBNET="${2:-$POD_SUBNET}"
      shift 2
      ;;
    -r | --vip-routeid-mappings)
      VIP_ROUTEID_MAPPING_DIR="${2:-$VIP_ROUTEID_MAPPING_DIR}"
      shift 2
      ;;
    -s | --service-subnet)
      SERVICE_SUBNET="${2:-$SERVICE_SUBNET}"
      shift 2
      ;;
    -u | --update-interval)
      UPDATE_INTERVAL="${2:-$UPDATE_INTERVAL}"
      shift 2
      ;;
    -v | --podip-vip-mappings)
      PODIP_VIP_MAPPING_DIR="${2:-$PODIP_VIP_MAPPING_DIR}"
      shift 2
      ;;
    --)
      shift
      break
      ;;
  esac
done

# Verify interface exists
ip addr show "${INTERFACE}" >/dev/null

trap "echo Stopping $NAME; if [ -n "${UPDATE_INTERVAL}" ];then delete; fi" SIGTERM SIGINT

if [ $DELETE == true ];then
  delete
  exit 0
fi

while :; do
  apply

  if [[ -z "${UPDATE_INTERVAL}" ]];then
    exit 0
  fi
  sleep "${UPDATE_INTERVAL}"
done

exit 0
