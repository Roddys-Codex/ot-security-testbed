# save as modbus_rw.py ; run: python3 modbus_rw.py 10.11.0.3
import sys
from pymodbus.client import ModbusTcpClient
host = sys.argv[1] if len(sys.argv)>1 else "10.11.0.3"

c = ModbusTcpClient(host, port=502)
assert c.connect(), "Modbus connect failed"

# Read first 10 holding registers
rr = c.read_holding_registers(0, 10)
print("HR[0..9]:", rr.registers if not rr.isError() else rr)

# Try flipping coil 0
wr = c.write_coil(0, True); print("Write coil 0 ON:", wr)
wr = c.write_coil(0, False); print("Write coil 0 OFF:", wr)

# Write holding register 1 to value 1234 (CAUTION: choose non-critical index)
wr = c.write_register(1, 1234); print("Write HR1=1234:", wr)

c.close()
