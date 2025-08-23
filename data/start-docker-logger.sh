#!/usr/bin/env bash
set -euo pipefail

LOG_DIR=./container-logs
mkdir -p "$LOG_DIR"

containers=(
  ot-security-testbed-influxdb-1
  ot-security-testbed-shellinabox-1
  ot-security-testbed-industrial-process-1
  ot-security-testbed-kapacitor-1
  ot-security-testbed-attacker-1
  ot-security-testbed-telegraf-1
  ot-security-testbed-openplc-1
  ot-security-testbed-chronograf-1
  ot-security-testbed-webserver-1
  ot-security-testbed-fuxa-1
)

for c in "${containers[@]}"; do
  # skip if container doesn't exist
  if ! docker ps -a --format '{{.Names}}' | grep -Fxq "$c"; then
    echo "WARN: container $c not found, skipping" >&2
    continue
  fi

  f="$LOG_DIR/$c.log"
  pid="$LOG_DIR/$c.pid"

  # if a follower is already running, skip
  if [[ -f "$pid" ]] && ps -p "$(cat "$pid")" >/dev/null 2>&1; then
    echo "Already following $c (pid $(cat "$pid"))"
    continue
  fi

  echo "[$(date -Is)] starting follower for $c -> $f"
  nohup bash -c '
    while :; do
      docker logs -f --timestamps --since=1s "'"$c"'" >> "'"$f"'" 2>&1 || true
      echo "[re-attaching '"$c"'] $(date -Is)" >> "'"$f"'"
      sleep 1
    done
  ' >/dev/null 2>&1 &
  echo $! > "$pid"
done
