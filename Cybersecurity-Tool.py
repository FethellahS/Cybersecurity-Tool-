from scapy.all import *
import logging

# Setup logging
logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO)

# Function to scan a single port
def scan_port(target_ip, port):
    # Create a TCP SYN packet
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    
    if response is None:
        return "Closed"
    elif response.haslayer(TCP) and response[TCP].flags == "SA":
        return "Open"
    else:
        return "Filtered"

# Function to scan a range of ports
def scan_ports(target_ip, port_range):
    open_ports = []
    for port in port_range:
        result = scan_port(target_ip, port)
        if result == "Open":
            open_ports.append(port)
            logging.info(f"Port {port} is open.")
    return open_ports

# Function to check for common vulnerabilities
def check_vulnerabilities(target_ip, open_ports):
    # Placeholder for vulnerability checks
    # E.g., checking for outdated services, known exploits, etc.
    for port in open_ports:
        # Example vulnerability check (placeholder)
        logging.info(f"Checking vulnerabilities on port {port}.")

def main():
    target_ip = input("Enter the target IP address: ")
    port_range = range(1, 1025)  # Scan ports from 1 to 1024
    
    logging.info(f"Starting scan on {target_ip}...")
    open_ports = scan_ports(target_ip, port_range)
    
    if open_ports:
        logging.info(f"Open ports found: {open_ports}")
        check_vulnerabilities(target_ip, open_ports)
    else:
        logging.info("No open ports found.")

if __name__ == "__main__":
    main()
