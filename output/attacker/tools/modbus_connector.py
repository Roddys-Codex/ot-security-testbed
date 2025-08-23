from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('10.11.0.20', port=502)
connection = client.connect() 
if connection:     
	print("Connected to Modbus device") 
else:     
	print("Failed to connect to Modbus device")
