from scapy.all import sniff

def packet_callback(packet):
    # Print out packet summary
    print(packet.summary())
    # You can organize the data into a 2D array here as per your requirements
    packets_2d_array.append([packet.time, packet.summary()])

if __name__ == "__main__":
    packets_2d_array = []
    
    print("Starting packet capture...")
    # Capture 10 packets for demo purposes (you can adjust this number as needed)
    sniff(count=10, prn=packet_callback)
    
    # Print the 2D array
    for pkt in packets_2d_array:
        print(pkt)
