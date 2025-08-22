import nmap
import subprocess

# Define the Docker subnet based on 'ip a' output
DOCKER_SUBNET = "10.11.0.0/16"

# Define ICS Ports of Interest
ICS_PORTS = [502, 4840]  # Modbus, OPC UA

def ping_sweep(subnet):
    print(f"[+] Scanning subnet {subnet} for live hosts...")
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')
    live_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            live_hosts.append(host)
    print(f"[+] Found {len(live_hosts)} live hosts: {live_hosts}")
    return live_hosts

def service_scan(hosts, ports):
    nm = nmap.PortScanner()
    print(f"[+] Scanning {len(hosts)} hosts for ICS services...")
    for host in hosts:
        port_str = ','.join(str(p) for p in ports)
        print(f"  -> Scanning {host} for ports {port_str}")
        nm.scan(hosts=host, arguments=f'-sV -p {port_str}')
        for port in ports:
            if nm[host].has_tcp(port) and nm[host]['tcp'][port]['state'] == 'open':
                service = nm[host]['tcp'][port]['name']
                version = nm[host]['tcp'][port]['version']
                print(f"    [+] {host}:{port} - Service: {service}, Version: {version}")

def main():
    live_hosts = ping_sweep(DOCKER_SUBNET)
    if live_hosts:
        service_scan(live_hosts, ICS_PORTS)
    else:
        print("[-] No live hosts found. Check network settings.")

if __name__ == "__main__":
    # Ensure nmap is installed in container
    try:
        subprocess.run(["nmap", "-v"], check=True)
        main()
    except subprocess.CalledProcessError:
        print("[-] nmap not found. Please install it using: apt update && apt install nmap -y")
