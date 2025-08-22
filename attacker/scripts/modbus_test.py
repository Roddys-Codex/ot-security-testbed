from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('openplc', port=502)
client.write_coils(0, [True, False, True])
