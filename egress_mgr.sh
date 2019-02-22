#!/bin/bash

set -e

# Parse Options
NAME=$(basename $0 | tr - ' ')
OPTS=$(getopt --options hf:n:m:u: --longoptions help,file:,namespace:,mapping-name:,update-interval: --name "$NAME" -- "$@")
[[ $? != 0 ]] && echo "Failed parsing options" >&2 && exit 1
eval set -- "$OPTS"

# Variables
CONFIG_FILE="./config.txt"
NAMESPACE="default"
MAPPING_NAME="podip-vip-mappings"
UPDATE_INTERVAL=

# Functions
function help() {
  cat << EOF
Updates configmap for podip_vip_mapping by checking current pod ip and config file
Usage:
  $NAME [options]
Options:
  -h, --help                 Displays the help text
  -f, --file                 Config file to specify mappings for pod and vip. Default is ${CONFIG_FILE}
  -n, --namespace            Namespace for configmap which stores mappings for pod ip and vip. Default is ${NAMESPACE}
  -m, --mapping-name         Name for configmap which stores mappings for pod ip and vip. Default is ${MAPPING_NAME}
  -u, --update-interval      How often to update configmap upon pod ip changes and config file changes. Default is empty for run once
EOF
}

function update_podip_vip_mapping () {
  # CONF is formated as space separated values. Values show namespace, name, and vip.
  # ex)
  # default pod1 192.168.1.1
  # namespace1 pod2 192.168.1.2
  CONF=$(cat "${CONFIG_FILE}")

  # POD_INFO is formated as space separated values. Values show namespace, name, and podip.
  # ex)
  # default pod1 10.244.1.1
  # default pod2 10.244.1.2
  # namespace1 pod1 10.244.1.3
  # namespace1 pod2 10.244.1.4
  POD_INFO=$(kubectl get pod --all-namespaces -o=custom-columns=ns:metadata.namespace,name:metadata.name,ip:status.podIP --no-headers)

  configmap_data=""

  while read ns name vip;do
    # Find podip in POD_INFO that matches to ns and name in CONF
    podip=$(echo "${POD_INFO}" | eval "awk '\$1 == \"${ns}\" && \$2 == \"${name}\" {print \$3}'")
    if [ -n "${podip}" ];then
      configmap_data="${configmap_data} --from-literal=${podip}=${vip}"
    else
      echo "Error: finding pod ip for namespace=${ns} name=${name}" >&2
    fi
  done <<< "${CONF}"

  # Output to configmap
  # ex) For above CONF and POD_INFO, data in configmap will be:
  # data:
  #   10.244.1.1: 192.168.1.1
  #   10.244.1.4: 192.168.1.2
  if ( kubectl get configmap -n "${NAMESPACE}" "${MAPPING_NAME}" >/dev/null 2>&1 );then
    # Replace existing configmap
    kubectl create configmap -n "${NAMESPACE}" "${MAPPING_NAME}" ${configmap_data} -o yaml --dry-run | kubectl replace -f -
  else
    # Create new configmap
    kubectl create configmap -n "${NAMESPACE}" "${MAPPING_NAME}" ${configmap_data} -o yaml --dry-run | kubectl apply -f -
  fi
}

while true
do
  case "$1" in
    -h | --help)
      help
      exit 0
      ;;
    -f | --file)
      CONFIG_FILE="${2:-$CONFIG_FILE}"
      shift 2
      ;;
    -n | --namespace)
      NAMESPACE="${2:-$NAMESPACE}"
      shift 2
      ;;
    -m | --mapping-name)
      MAPPING_NAME="${2:-$MAPPING_NAME}"
      shift 2
      ;;
    -u | --update-interval)
      UPDATE_INTERVAL="${2:-$UPDATE_INTERVAL}"
      shift 2
      ;;
    --)
      shift
      break
      ;;
  esac
done

update_podip_vip_mapping

while [[ -n "${UPDATE_INTERVAL}" ]]; do
  sleep "${UPDATE_INTERVAL}"
  update_podip_vip_mapping
done

exit 0
