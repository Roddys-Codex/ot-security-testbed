from pymodbus.client import ModbusTcpClient
 
client = ModbusTcpClient('10.11.0.20') 
print("Setting coil 1 to false") 
client.write_coil(1, False) 
result = client.read_coils(1,1) 
print("Coil 1 state: " + str(result.bits[0]))
 
print("Setting coil 1 to true") 
client.write_coil(1, True) 
result = client.read_coils(1,1) 
print("Coil 1 state: " + str(result.bits[0]))
 
client.close()
