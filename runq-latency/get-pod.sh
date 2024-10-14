#!/bin/bash

# Display pod information about a process, using its host PID as input

set -euo pipefail

usage() {
  cat << EOD

Usage: `basename $0` PID

  Available options:
    -h          this message

Display pod information about a process, using its host PID as input:
- display namespace, pod, container, and primary process pid for this container if the process is running in a pod
- else exit with code 1
EOD
}

if [ $# -ne 1 ] ; then
    usage
    exit 2
fi

pid=$1
is_running_in_pod=false

pod=$(nsenter -t $pid -u hostname 2>&1)
if [ $? -ne 0 ]
then
    printf "%s %s:\n %s" "nsenter command failed for pid" "$pid" "$pod"
fi

cids=$(crictl ps -q)
for cid in $cids
do
  current_pod=$(crictl inspect -o go-template --template '{{ index .info.config.labels "io.kubernetes.pod.name"}}' "$cid")
  if [ "$pod" == "$current_pod" ]
  then
    tmpl='NS:{{ index .info.config.labels "io.kubernetes.pod.namespace"}} POD:{{ index .info.config.labels "io.kubernetes.pod.name"}} CONTAINER:{{ index .info.config.labels "io.kubernetes.container.name"}} PRIMARY PID:{{.info.pid}}'
    crictl inspect --output go-template --template "$tmpl" "$cid"
    is_running_in_pod=true
    break
  fi
done

if [ "$is_running_in_pod" = false ]
then
  echo "Process $pid is not running in a pod."
  exit 1
fi
