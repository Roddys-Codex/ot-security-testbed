Running network sniffers

chmod +x pcap-sniffers.sh
./pcap-sniffers.sh start         # auto-discovers & starts per-container captures
./pcap-sniffers.sh status        # see sniffer containers & latest files
ls -lht ./data/captures | head   # files should appear quickly if traffic matches

# Optional: limit to specific containers
./pcap-sniffers.sh start ot-security-testbed-openplc-1 ot-security-testbed-industrial-process-1

# Stop all sniffers
./pcap-sniffers.sh stop

Running docker container loggers 
chmod +x docker_logger.sh
./docker_logger.sh   # or: bash docker_logger.sh

for p in ./container-logs/*.pid; do kill "$(cat "$p")" 2>/dev/null || true; done
rm -f ./container-logs/*.pid

# Simplist way for full data capture is to run
./start-data-capture.sh

then run 

stop-data-capture.sh

when you are finished collecting data.


pcaps will be output to the 'capture' folder.
logs will be output to the 'container-logs' folder.
