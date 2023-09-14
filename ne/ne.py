from scapy.all import sniff, IP, TCP, UDP
import ipaddress

# Global variables
n = 10  # Dimensions for our 2D array (10x10)
current_2d_array = []  # Current 2D array that's being filled
packets_3d_array = []  # 3D array containing filled 2D arrays

def ip_to_binary(ip):
    """
    Convert an IP address to its binary representation.
    """
    return format(int(ipaddress.ip_address(ip)), '032b')

def protocol_to_binary(proto):
    """
    Convert a protocol number to its binary representation.
    """
    return format(proto, '08b')

def preprocess_packet(packet):
    """
    Extract necessary information from a packet for attack detection, in binary format.
    """
    binary_representation = []

    if IP in packet:
        src_ip_binary = ip_to_binary(packet[IP].src)
        dst_ip_binary = ip_to_binary(packet[IP].dst)
        
        binary_representation.extend([src_ip_binary, dst_ip_binary])

        if TCP in packet or UDP in packet:
            proto = protocol_to_binary(packet[IP].proto)
            binary_representation.append(proto)

    return binary_representation

def packet_callback(packet):
    """
    Callback function to handle incoming packets.
    Organizes packets into 2D arrays, and pushes filled 2D arrays into a 3D array.
    """
    global current_2d_array
    processed_data = preprocess_packet(packet)
    
    if processed_data:
        current_2d_array.extend(processed_data)
    
    # If the current 2D array is full
    if len(current_2d_array) >= n * n:
        # Reshape to nxn
        square_2d_array = [current_2d_array[i:i+n] for i in range(0, n*n, n)]
        packets_3d_array.append(square_2d_array)
        current_2d_array = []

if __name__ == "__main__":
    print("Starting packet capture...")
    # Continuously capture packets
    sniff(prn=packet_callback)

    # For visualization or debugging purposes
    # for block in packets_3d_array:
    #     for row in block:
    #         print(row)
    #     print("-----------------------")
