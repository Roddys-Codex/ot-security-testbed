#!/usr/bin/env bash
set -euo pipefail

# ===== Config =====
PROJECT_PREFIX="ot-security-testbed-"
CAPTURE_DIR="./captures"
ROTATE_SECS="${ROTATE_SECS:-300}"   # seconds per file (time-based rotation)
ROTATE_COUNT="${ROTATE_COUNT:-24}"  # number of files to keep
IMAGE="nicolaka/netshoot"           # contains tcpdump
SNIFFER_PREFIX="pcap-"              # prefix for sniffer container names we create

mkdir -p "$CAPTURE_DIR"
# make the mount path absolute (helps docker on some hosts)
CAPTURE_DIR="$(cd "$CAPTURE_DIR" && pwd)"

# Return a display/role name used in filenames from a container NAME
role_of () {
  # strip project prefix and trailing -N (compose suffix)
  local name="$1"
  role="${name#${PROJECT_PREFIX}}"           # remove prefix
  role="${role%-[0-9]*}"                     # remove -1 / -2 suffixes
  printf '%s' "$role"
}

# Return a tcpdump filter string tailored per role
filter_for () {
  local role="$1"
  case "$role" in
    openplc)
      echo '(arp or port 502 or port 4840 or port 8080 or port 5020)'
      ;;
    industrial-process)
      echo '(arp or port 5020 or port 4840 or port 8000)'
      ;;
    telegraf)
      echo '(arp or port 502 or port 5020 or port 4840 or port 8086)'
      ;;
    influxdb)
      echo '(arp or port 8086)'
      ;;
    chronograf)
      echo '(arp or port 8888)'
      ;;
    kapacitor)
      echo '(arp or port 9092 or port 8086)'
      ;;
    attacker)
      echo '(not port 22)'
      ;;
    shellinabox)
      echo '(arp or port 4200)'
      ;;
    *)
      # default: all common ICS ports in your stack
      echo '(arp or port 502 or port 5020 or port 4840 or port 8080 or port 8086 or port 8888 or port 9092 or port 4200)'
      ;;
  esac
}

# Build list of target containers:
#  - must start with project prefix
#  - exclude any we spawn ourselves (prefix pcap-)
discover_targets () {
  docker ps --format '{{.Names}}' \
    | grep -E "^${PROJECT_PREFIX}" \
    | grep -vE "^${SNIFFER_PREFIX}" \
    | sort
}

sniffer_name_for () {  # pcap container name for a target
  printf '%s%s' "$SNIFFER_PREFIX" "$1"
}

start_one () {
  local target="$1"
  local sname; sname="$(sniffer_name_for "$target")"
  local role; role="$(role_of "$target")"
  local filter; filter="$(filter_for "$role")"

  # Skip if already running
  if docker ps --format '{{.Names}}' | grep -Fxq "$sname"; then
    echo "Already running: $sname (for $target)"
    return 0
  fi

  echo "Starting sniffer $sname (role=$role) for $target"
  docker run -d --name "$sname" \
    --network="container:${target}" \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "${CAPTURE_DIR}:/captures" \
    "$IMAGE" \
    tcpdump -i any -nn -U \
      -w "/captures/${role}_%Y-%m-%d_%H-%M-%S.pcap" \
      -G "$ROTATE_SECS" -W "$ROTATE_COUNT" \
      "$filter" >/dev/null

  # Quick sanity: print argv and first lines of tcpdump output (if any error)
  sleep 0.5
  if ! docker ps --format '{{.Names}}' | grep -Fxq "$sname"; then
    echo "ERROR: sniffer $sname failed to start (check docker logs $sname)" >&2
  fi
}

stop_one () {
  local target="$1"
  local sname; sname="$(sniffer_name_for "$target")"
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$sname"; then
    echo "Stopping $sname"
    docker rm -f "$sname" >/dev/null || true
  fi
}

start_all () {
  local targets=()
  if [ "$#" -gt 0 ]; then
    targets=( "$@" )
  else
    mapfile -t targets < <(discover_targets)
  fi
  if [ "${#targets[@]}" -eq 0 ]; then
    echo "No target containers found. Are your services up?" >&2
    exit 1
  fi
  echo "Capture dir: $CAPTURE_DIR"
  echo "Rotation: every ${ROTATE_SECS}s, keep ${ROTATE_COUNT} files"
  for t in "${targets[@]}"; do
    start_one "$t"
  done
}

stop_all () {
  # Stop all sniffers we created (pcap-*)
  mapfile -t sniffers < <(docker ps -a --format '{{.Names}}' | grep -E "^${SNIFFER_PREFIX}" || true)
  if [ "${#sniffers[@]}" -eq 0 ]; then
    echo "No sniffer containers to stop."
    return 0
  fi
  echo "Stopping: ${sniffers[*]}"
  docker rm -f "${sniffers[@]}" >/dev/null || true
}

status_all () {
  echo "=== Running sniffers ==="
  docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E "^${SNIFFER_PREFIX}" || echo "(none)"
  echo
  echo "=== Latest capture files ==="
  ls -lht "${CAPTURE_DIR}" | head || true
}

usage () {
  cat <<EOF
Usage: $0 {start|stop|status} [container_name ...]
  start   - start sniffers for all project containers (or only the ones listed)
  stop    - stop all sniffer containers (pcap-*)
  status  - show running sniffers and latest files
Env vars:
  ROTATE_SECS (default ${ROTATE_SECS}), ROTATE_COUNT (default ${ROTATE_COUNT})
Capture dir: ${CAPTURE_DIR}
EOF
}

cmd="${1:-}"; shift || true
case "$cmd" in
  start)  start_all "$@";;
  stop)   stop_all;;
  status) status_all;;
  *)      usage; exit 1;;
esac
