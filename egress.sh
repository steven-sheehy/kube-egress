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
PODIP_VIP_MAPPING_DIR="/etc/kube-egress/podip_vip_mapping/"
VIP_ROUTEID_MAPPING_DIR="/etc/kube-egress/vip_routeid_mapping/"
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

function delete_rule() {
  local table=${1}
  shift
  # Remove the duplicated rule by replacing the output of iptables -S
  eval $(echo $* | sed "s/^-A/iptables -t ${table} -D/") 2>/dev/null || true
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
          echo "duplicated"
          delete_rule "${table}" ${rule}
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

function get_ip_without_netmask() {
  local ip=${1}
  echo "${ip}" | awk -F '/' '{print $1}'
}

function get_decimal_routeid_without_mask() {
  local mark=${1}
  printf "%d" $(echo "${mark}" | awk -F '/' '{print $1}')
}

function is_vip_routeid_mapping_correct() {
  local VIP=${1}
  local EXPECTED_ROUTEID=${2}
  local ret=false

  # Check if route_id for vip that is mapped with podip is correct
  if [[ -n "${VIP_ROUTEID_MAPPINGS[$VIP]+unset}" ]];then
    local ROUTEID_IN_MAPPINGS="${VIP_ROUTEID_MAPPINGS[$VIP]}"
    if [ "${EXPECTED_ROUTEID}" == "${ROUTEID_IN_MAPPINGS}" ];then
      ret=true
    fi
  fi
  echo ${ret}
}

function is_pod_ip_routeid_mapping_correct() {
  local POD_IP=${1}
  local ROUTEID=${2}
  local ret=false

  # Check if POD_IP is defined in PODIP_VIP_MAPPINGS
  if [[ -n "${PODIP_VIP_MAPPINGS[$POD_IP]+unset}" ]];then
    local VIP="${PODIP_VIP_MAPPINGS[$POD_IP]}"
    if (is_vip_routeid_mapping_correct "${VIP}" "${ROUTEID}" | grep -Fq 'true');then
      ret=true
    fi
  fi
  echo ${ret}
}

function is_routeid_exist() {
  local EXPECTED_ROUTEID=${1}
  local ret=false

  for VIP in "${!VIP_ROUTEID_MAPPINGS[@]}"; do
    ROUTEID_IN_MAPPINGS="${VIP_ROUTEID_MAPPINGS[$VIP]}"
    if [ "${EXPECTED_ROUTEID}" == "${ROUTEID_IN_MAPPINGS}" ];then
      ret=true
    fi
  done

  echo ${ret}
}

function delete_obsolete() {
  unset PODIP_VIP_MAPPINGS
  unset VIP_ROUTEID_MAPPINGS
  declare -A PODIP_VIP_MAPPINGS
  declare -A VIP_ROUTEID_MAPPINGS
  reload_mappings

  # Check EGRESS chain
  iptables -t mangle -S EGRESS | grep -F -- '-A EGRESS -s' \
  | while read rule;do
    # ex) rule is like below:
    # -A EGRESS -s 10.244.1.1/32 -j MARK --set-xmark 0x40/0xffffffff
    local POD_IP=$(get_ip_without_netmask $(echo "${rule}" | awk '{print $4}'))
    local ROUTEID=$(get_decimal_routeid_without_mask $(echo "${rule}" | awk '{print $8}'))

    # Check if route_id for vip that is mapped with podip is correct
    if ( is_pod_ip_routeid_mapping_correct "${POD_IP}" "${ROUTEID}" | grep -Fq 'false' );then
      delete_rule mangle ${rule}
    fi
  done

  # Check FORWARD chain
  iptables -t mangle -S FORWARD 2>/dev/null | grep -F -- '-A FORWARD -j' \
  | while read rule;do
    # ex) rule is like below:
    # -A FORWARD -j EGRESS_FWD_192.168.1.1
    local CHAIN=$(echo "${rule}" | awk '{print $4}')
    local VIP=$(echo "${CHAIN}" | awk -F '_' '{print $3}')
    if [[ -z "${VIP_ROUTEID_MAPPINGS[$VIP]+unset}" ]]; then
      # This VIP is not defined, so chain for this VIP is no longer needed.
      # Delete obsolete chain
      destroy_delete_chain mangle FORWARD "${CHAIN}"
      continue
    fi

    # Check EGRESS_FWD_* chains
    iptables -t mangle -S ${CHAIN} 2>/dev/null | grep -F -- '-A EGRESS_FWD_' \
    | while read rule;do
      # ex) rule is like below:
      # -A EGRESS_FWD_192.168.1.1 -s 10.244.1.1/32 -i eth0 -o eth0 -j MARK --set-xmark 0x40/0xffffffff
      local POD_IP=$(get_ip_without_netmask $(echo "${rule}" | awk '{print $4}'))
      local ROUTEID=$(get_decimal_routeid_without_mask $(echo "${rule}" | awk '{print $12}'))

      # Check if route_id for vip that is mapped with podip is correct
      if ( is_pod_ip_routeid_mapping_correct "${POD_IP}" "${ROUTEID}" | grep -Fq 'false' );then
        # Delete obsolete rule
        delete_rule mangle ${rule}
      fi
    done
  done

  # Check EGRESS_POST chain
  iptables -t nat -S EGRESS_POST 2>/dev/null | grep -F -- '-A EGRESS_POST' \
  | while read rule;do
    # ex) rules are like belows:
    #  (1)
    #     -A EGRESS_POST -j EGRESS_POST_192.168.1.1
    #  (2)
    #     -A EGRESS_POST -m mark --mark 0x40/0xff -j ACCEPT

    # Case (1)
    if ( echo "${rule}" | grep -Fq -- '-A EGRESS_POST -j' );then
      local CHAIN=$(echo "${rule}" | awk '{print $4}')
      local VIP=$(echo "${CHAIN}" | awk -F '_' '{print $3}')
      if [[ -z "${VIP_ROUTEID_MAPPINGS[$VIP]+unset}" ]];then
        # This VIP is not defined, so chain for this VIP is no longer needed.
        destroy_delete_chain nat EGRESS_POST "${CHAIN}"
        continue
      fi

      # Check EGRESS_POST_* chains
      iptables -t nat -S ${CHAIN} 2>/dev/null | grep -F -- '-A EGRESS_POST_' \
      | while read rule;do
        # ex) rule is like below:
        # -A EGRESS_POST_192.168.1.1 -o eth0 -m mark --mark 0x40/0xff -j SNAT --to-source 192.168.1.1
        local VIP=$(echo "${rule}" | awk '{print $12}')
        local ROUTEID=$(get_decimal_routeid_without_mask $(echo "${rule}" | awk '{print $8}'))

        # Check if vip and routeid are mapped correctly
        if ( is_vip_routeid_mapping_correct "${VIP}" "${ROUTEID}" | grep -Fq 'false' ) ;then
          delete_rule nat ${rule}
        fi
      done

    # Case (2)
    elif ( echo "${rule}" | grep -Fq -- '-A EGRESS_POST -m mark --mark' );then
      local ROUTEID=$(get_decimal_routeid_without_mask $(echo "${rule}" | awk '{print $6}'))
      # Check if vip and routeid are mapped correctly
      if ( is_routeid_exist "${ROUTEID}" | grep -Fq 'false' ) ;then
        # Delete obsolete rule
        delete_rule nat ${rule}
      fi
    fi
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
  delete_obsolete
  apply

  if [[ -z "${UPDATE_INTERVAL}" ]];then
    exit 0
  fi
  sleep "${UPDATE_INTERVAL}"
done

exit 0
