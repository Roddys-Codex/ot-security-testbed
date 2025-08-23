for p in ./container-logs/*.pid; do kill "$(cat "$p")" 2>/dev/null || true; done
rm -f ./container-logs/*.pid
