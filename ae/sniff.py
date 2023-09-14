from scapy.all import sniff, IP

# Global variables
n = 10  # Dimensions for our 2D array (10x10)
current_2d_array = []  # Current 2D array that's being filled
packets_3d_array = []  # 3D array containing filled 2D arrays

def preprocess_packet(packet):
    """
    Extract necessary information from a packet for attack detection.
    This function currently extracts source IP, destination IP, and the protocol.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        return [src_ip, dst_ip, protocol]
    return []

def packet_callback(packet):
    """
    Callback function to handle incoming packets.
    Organizes packets into 2D arrays, and pushes filled 2D arrays into a 3D array.
    """
    global current_2d_array
    processed_data = preprocess_packet(packet)
    
    if processed_data:
        current_2d_array.append(processed_data)
    
    # If the current 2D array is full
    if len(current_2d_array) >= n * n:
        packets_3d_array.append(current_2d_array)
        current_2d_array = []

if __name__ == "__main__":
    print("Starting packet capture...")
    # Continuously capture packets
    sniff(prn=packet_callback)

    # If you want to view the packets in 3D array
    # for block in packets_3d_array:
    #     for row in block:
    #         print(row)
    #     print("-----------------------")
