echo "Starting container network sniffers";
./pcap-sniffers.sh start;
echo "Starting docker container logging to file";
./start-docker-logger.sh;

