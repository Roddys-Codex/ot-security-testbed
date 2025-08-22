echo "Stopping container network sniffers."
./pcap-sniffers.sh stop;
echo "Stopping docker container logging to file.";
./stop-docker-logger.sh;
