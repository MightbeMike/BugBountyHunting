#thisas been used in my bug bounty hunting for web based vuln
#typicaly these ports are used for testing
import nmap

def nmap_scan(target):
    """
    Perform an Nmap scan on the target host to identify open ports and services.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 1-65535 -sV -T4')  # Scan all ports with version detection
    open_ports = []
    for host in nm.all_hosts():
        port_info = nm[host]['tcp']
        for port in port_info:
            if port_info[port]['state'] == 'open':
                open_ports.append({'port': port, 'service': port_info[port]['name'], 'protocol': port_info[port]['protocol']})
    return open_ports

def main():
    target_host = input("Enter the target host or IP address: ")
    print(f"Scanning target {target_host}...")
    open_ports = nmap_scan(target_host)
    if open_ports:
        print("Open ports/services found:")
        for port in open_ports:
            print(f"Port: {port['port']}, Service: {port['service']}, Protocol: {port['protocol']}")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
