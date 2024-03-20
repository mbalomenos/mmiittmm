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

def verify_target_reachability(target_ip, port):
    """Function to verify target device reachability and responsiveness."""
    try:
        explain_step(3, f"Verifying target device ({target_ip}) reachability and responsiveness...")

        # Attempt to establish a connection using telnet
        telnet_result = subprocess.run(["telnet", target_ip, str(port)], capture_output=True, timeout=5)
        if telnet_result.returncode == 0:
            logger.info(f"Telnet connection to {target_ip}:{port} successful.")
        else:
            logger.error(f"Telnet connection to {target_ip}:{port} failed.")

        # Attempt to establish a connection using netcat
        nc_result = subprocess.run(["nc", "-zv", target_ip, str(port)], capture_output=True, timeout=5)
        if nc_result.returncode == 0:
            logger.info(f"Netcat connection to {target_ip}:{port} successful.")
        else:
            logger.error(f"Netcat connection to {target_ip}:{port} failed.")

    except Exception as e:
        logger.error(f"Error verifying target device reachability: {e}")

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

        # Step 3: Verify target device reachability and responsiveness
        verify_target_reachability(chosen_device['ip'], 12345)  # Change the port number as needed

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
