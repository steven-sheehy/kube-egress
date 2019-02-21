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
    if [ "${config}" != "" ];then
      PODIP_VIP_MAPPINGS["${config}"]=$(cat "${PODIP_VIP_MAPPING_DIR}/${config}")
    fi
  done <<< "$(ls ${PODIP_VIP_MAPPING_DIR})"

  while read config;do
    if [ "${config}" != "" ];then
      VIP_ROUTEID_MAPPINGS["${config}"]=$(cat "${VIP_ROUTEID_MAPPING_DIR}/${config}")
    fi
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

  if (iptables -t "${table}" -nL "${chain}" >/dev/null 2>&1);then
    # Delete or flash chain only when there's existing chain
    if [ "${action}" == "-X" ] || [ "${action}" == "-F" ];then
      iptables -t "${table}" "${action}" "${chain}" 2>/dev/null || true
    fi
  else
    # Create chain only when there's no existing chain
    if [ "${action}" == "-N" ];then
      iptables -t "${table}" "${action}" "${chain}" 2>/dev/null || true
    fi
  fi
}

function handle_rule() {
  local table_opt=${1}
  local table=${2}
  local action=${3}
  local chain=${4}
  shift 4

  if (iptables -t "${table}" -C "${chain}" $@ 2>/dev/null);then
    # Delete rule only when there's existing rule
    if [ ${action} == "-D" ];then
      iptables -t "${table}" "${action}" "${chain}" $@ 2>/dev/null || true
    fi
  else
    # Add or insert rule only when there's no existing rule
    if [ "${action}" == "-A" ] || [ "${action}" == "-I" ];then
      iptables -t "${table}" "${action}" "${chain}" $@ 2>/dev/null || true
    fi
  fi
}

function create_add_chain() {
  local table=${1}
  local parent_chain=${2}
  local child_chain=${3}

  handle_chain -t "${table}" -N "${child_chain}"
  handle_rule -t "${table}" -A "${parent_chain}" -j "${child_chain}"
}

function create_insert_chain() {
  local table=${1}
  local parent_chain=${2}
  local child_chain=${3}

  handle_chain -t "${table}" -N "${child_chain}"
  handle_rule -t "${table}" -I "${parent_chain}" -j "${child_chain}"
}

function destroy_delete_chain() {
  local table=${1}
  local parent_chain=${2}
  local child_chain=${3}

  handle_rule -t "${table}" -D "${parent_chain}" -j "${child_chain}"
  handle_chain -t "${table}" -F "${child_chain}"
  handle_chain -t "${table}" -X "${child_chain}"
}

function apply() {
  unset PODIP_VIP_MAPPINGS
  unset VIP_ROUTEID_MAPPINGS
  declare -A PODIP_VIP_MAPPINGS
  declare -A VIP_ROUTEID_MAPPINGS
  reload_mappings

  log "Applying common iptables rules"
  create_insert_chain nat POSTROUTING EGRESS_POST
  create_add_chain mangle PREROUTING EGRESS
  handle_rule -t mangle -I EGRESS -d "${POD_SUBNET}" -j RETURN
  handle_rule -t mangle -I EGRESS -d "${SERVICE_SUBNET}" -j RETURN

  unset configured_vips
  declare -A configured_vips

  for POD_IP in "${!PODIP_VIP_MAPPINGS[@]}"; do
    VIP="${PODIP_VIP_MAPPINGS[$POD_IP]}"
    ROUTE_ID="${VIP_ROUTEID_MAPPINGS[$VIP]}"
    ROUTE_TABLE="${ROUTE_TABLE_PREFIX}_${ROUTE_ID}"
    EGRESS_FWD_CHAIN="EGRESS_FWD_${VIP}"
    EGRESS_POST_CHAIN="EGRESS_POST_${VIP}"
    VIP_CONFIGURED=false

    # Add common per pod rules
    handle_rule -t mangle -A EGRESS -s "${POD_IP}" -j MARK --set-mark "${ROUTE_ID}"

    # Check if VIP has already been configured in this loop
    if [[ -z "${configured_vips[$VIP]+unset}" ]]; then
      # Define and add chains for VIP
      create_add_chain mangle FORWARD "${EGRESS_FWD_CHAIN}"
      create_insert_chain nat EGRESS_POST "${EGRESS_POST_CHAIN}"
      configured_vips["${VIP}"]=true
    else
      VIP_CONFIGURED=true
    fi

    # Egress nodes
    if (ip -o addr show "${INTERFACE}" | grep -Fq "${VIP}"); then
      log "VIP ${VIP} for ${POD_IP} transitioned to primary"
      # Per VIP rules
      if [ "${VIP_CONFIGURED}" == "false" ]; then
        # Delete rules for secondory
        handle_rule -t nat -D EGRESS_POST -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j ACCEPT
        ip rule del table "${ROUTE_TABLE}" 2>/dev/null || true
        ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
        rm -f "/etc/iproute2/rt_tables.d/${ROUTE_TABLE}.conf"
      fi
      # Per pod rules
      # Add rules for primary
      handle_rule -t mangle -A "${EGRESS_FWD_CHAIN}" -s "${POD_IP}" -i "${INTERFACE}" -o "${INTERFACE}" -j MARK --set-mark "${ROUTE_ID}"
      handle_rule -t nat -A "${EGRESS_POST_CHAIN}" -o "${INTERFACE}" -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j SNAT --to "${VIP}"
    # Non-egress nodes
    else
      # Per VIP rules
      if [ "${VIP_CONFIGURED}" == "false" ]; then
        # Add rules for secondary
        log "VIP ${VIP} transitioned to secondary"
        handle_rule -t nat -A EGRESS_POST -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j ACCEPT
        echo "${ROUTE_ID} ${ROUTE_TABLE}" > "/etc/iproute2/rt_tables.d/${ROUTE_TABLE}.conf"
        if ! (ip route show table ${ROUTE_ID} | grep -Fq "${VIP}"); then
          ip route add default via "${VIP}" dev "${INTERFACE}" table "${ROUTE_TABLE}"
        fi
        if ! (ip rule show | grep -Fq "${ROUTE_TABLE}"); then
          ip rule add fwmark "${ROUTE_ID}" table "${ROUTE_TABLE}"
        fi
      fi
      # Per pod rules
      # Delete rules for primary
      handle_rule -t mangle -D "${EGRESS_FWD_CHAIN}" -s "${POD_IP}" -i "${INTERFACE}" -o "${INTERFACE}" -j MARK --set-mark "${ROUTE_ID}"
      handle_rule -t nat -D "${EGRESS_POST_CHAIN}" -o "${INTERFACE}" -m mark --mark "${ROUTE_ID}/${ROUTE_ID_MASK}" -j SNAT --to "${VIP}"
    fi
  done

  ip route flush cache
}

function delete_duplicated() {
  local table=${1}
  local chain=${2}
  local filter="${3}"
  local attempt=0
  local max_attempt=5

  while [ ${attempt} -lt ${max_attempt} ];do
    local count=0
    while read rule;do
      if [ "${rule}" != "" ];then
        if [ "${filter}" = "*" ] || (echo "${rule}" | grep -Fq "${filter}");then
          # Remove the duplicated rule by replacing the output of iptables -S
          eval $(echo "${rule}" | sed "s/^-A/iptables -t ${table} -D/") 2>/dev/null || true
          count=$((${count} + 1))
        fi
      fi
    done <<< $(iptables -t "${table}" -S "${chain}" 2>/dev/null | sort | uniq -d)

    # Check if there are any updates in this loop
    if [ ${count} -eq 0 ];then
      # Break the loop (Trap doesn't work well with break, so update attempt count instead.)
      attempt=${max_attempt}
    else
      attempt=$(( ${attempt} + 1 ))
    fi
  done
}

function delete_all_duplicated() {
  delete_duplicated mangle PREROUTING EGRESS
  delete_duplicated mangle EGRESS "*"
  delete_duplicated mangle FORWARD EGRESS_FWD
  delete_duplicated nat POSTROUTING EGRESS_POST
  delete_duplicated nat EGRESS_POST "*"

  iptables -t mangle -nL FORWARD 2>/dev/null | awk '/EGRESS_FWD_/{print $1}' \
  | while read chain;do
    delete_duplicated mangle "${chain}" "*"
  done

  iptables -t nat -nL EGRESS_POST 2>/dev/null | awk '/EGRESS_POST_/{print $1}' \
  | while read chain;do
    delete_duplicated nat "${chain}" "*"
  done
}

function delete_all() {
  log "Deleting all rules"
  delete_all_duplicated

  # Delete per VIP iptables chains
  iptables -t mangle -nL FORWARD 2>/dev/null | awk '/EGRESS_FWD_/{print $1}' \
  | while read chain;do
    destroy_delete_chain mangle FORWARD "${chain}"
  done

  iptables -t nat -nL EGRESS_POST 2>/dev/null | awk '/EGRESS_POST_/{print $1}' \
  | while read chain;do
    destroy_delete_chain nat EGRESS_POST "${chain}"
  done

  # Delete common iptables chains
  destroy_delete_chain nat POSTROUTING EGRESS_POST
  destroy_delete_chain mangle PREROUTING EGRESS

  # Delete all routing tables
  ip rule show | awk '/egress_/{print $7}' \
  | while read ROUTE_TABLE;do
    ip rule del table "${ROUTE_TABLE}" 2>/dev/null || true
    ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
  done

  find /etc/iproute2/rt_tables.d/ -regex '/etc/iproute2/rt_tables.d/egress_[0-9]+.conf' \
  | while read ROUTE_FILE;do
    rm -f "${ROUTE_FILE}"
  done

  ip route flush cache
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

trap "echo Stopping $NAME; if [ -n "${UPDATE_INTERVAL}" ];then delete_all; fi" SIGTERM SIGINT

if [ $DELETE == true ];then
  delete_all
  exit 0
fi

while :; do
  delete_all_duplicated
  apply

  if [[ -z "${UPDATE_INTERVAL}" ]];then
    exit 0
  fi
  sleep "${UPDATE_INTERVAL}"
done

exit 0
