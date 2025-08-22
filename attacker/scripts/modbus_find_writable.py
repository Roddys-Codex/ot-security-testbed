# modbus_find_writable.py (safe, tiny probe)
# usage: python3 modbus_find_writable.py 10.11.0.3
import sys, time
from pymodbus.client import ModbusTcpClient
host = sys.argv[1] if len(sys.argv)>1 else "10.11.0.3"
c = ModbusTcpClient(host, port=502); assert c.connect()
# Try first few coils
for addr in range(0, 6):
    c.write_coil(addr, True); time.sleep(0.5); c.write_coil(addr, False)
# Try a couple holding registers (pick non-critical small indices)
for hr in range(0, 4):
    c.write_register(hr, 100 + hr)  # harmless values you can later revert
c.close()
