from scapy.all import sniff, IP

def packet_callback(packet):
    # Check if the packet has the IP layer
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip not in packets_dict:
            packets_dict[src_ip] = []

        # Append the packet summary (or the whole packet if needed) to the list for the source IP
        packets_dict[src_ip].append(packet.summary())

if __name__ == "__main__":
    packets_dict = {}
    
    print("Starting packet capture...")
    # Capture 50 packets for demo purposes (you can adjust this number as needed)
    sniff(count=50, prn=packet_callback)

    # Convert dictionary to 2D array
    packets_2d_array = []
    for src_ip, packets in packets_dict.items():
        packets_2d_array.append([src_ip] + packets)

    # Print the 2D array
    for block in packets_2d_array:
        print("Source IP:", block[0])
        for pkt in block[1:]:
            print("\t", pkt)
        print("-----------------------")
