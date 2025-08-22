Strong secure recon (prefers S&E on strongest policy):

node opc-ua-enumerator.mjs \
  --endpoint opc.tcp://plc:4840 \
  --pattern 'heater|valve|pump|setpoint' \
  --maxDepth 6 --maxPerBrowse 500 \
  --evidence /evidence


Allow lab fallback to None/None if server only exposes insecure:

node opc-ua-enumerator.mjs \
  --endpoint opc.tcp://plc:4840 \
  --allowInsecure \
  --evidence /evidence


Force Basic256Sha256 + S&E on the industrial-process server:

node opc-ua-enumerator.mjs \
  --endpoint opc.tcp://industrial-process:4840 \
  --forcePolicy Basic256Sha256 \
  --forceMode SignAndEncrypt \
  --pattern '' --maxDepth 5 \
  --evidence /evidence


If a server advertises a secure policy but temporarily rejects a mode, 
you’ll now see it try SignAndEncrypt then Sign automatically before giving up, 
which should eliminate the “policy X / mode None” mismatch and the resulting disconnects/timeouts you hit.

What you get (Phase-1 evidence)

/evidence/opcua_phase1_evidence.jsonl — endpoints, server-cert SHA1, namespaces, per-node “inspect” records (filtered by --pattern).

/evidence/certs/<host>-server.der + .sha1 — pinned server certs (also placed into your PKI/trusted for clean trust).

/evidence/opcua_snapshot.csv — variable snapshot with access bits and current value (read-only).

This lines up with INCONTROLLER-style Phase-1: discover control points & security posture, pin certs, and produce reusable artifacts for Phase-2 selection and Phase-3 impact.
