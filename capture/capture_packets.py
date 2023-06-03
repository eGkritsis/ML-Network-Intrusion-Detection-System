from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
#from capture.traffic_report import generate_report

# Empty captured packets list
captured_packets = []

# Capture packets
def capture_packets(interface, num_packets):
    # Start packet capturing and call the packet_callback for each captured packet
    sniff(iface=interface, count=num_packets, prn=packet_callback)

# Packet processing callback function
def packet_callback(packet):

    try: 
        # Append packet to the captured packets list 
        captured_packets.append(packet)
        print(packet.summary())
    except Exception as e:
        print(f"Error processing packet: {e}")



import os
from datetime import datetime


def generate_report(captured_packets):
    # Create a unique filename using the current date and time
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report_{timestamp}.txt"

    # Packet number
    n = 0

    # Open the report file for writing
    with open(filename, 'w') as report_file:
        report_file.write("Network Traffic Report\n")
        report_file.write("======================\n\n")

        # Iterate over the captured packet data
        for packet in captured_packets:
            # Increase packet number
            n = n + 1
            try:
                # Check if the packet has the IP layer
                if IP in packet:
                    # Extract information from the packet
                    source_ip = packet[IP].src
                    destination_ip = packet[IP].dst
                    source_port = packet[TCP].sport
                    destination_port = packet[TCP].dport
                    packet_size = len(packet)

                    # Write the extracted information to the report file
                    report_file.write(f"*Packet #{n}*\n")
                    report_file.write(f"Source IP: {source_ip}\n")
                    report_file.write(f"Destination IP: {destination_ip}\n")
                    report_file.write(f"Source Port: {source_port}\n")
                    report_file.write(f"Destination Port: {destination_port}\n")
                    report_file.write(f"Packet Size: {packet_size} bytes\n\n")
                    report_file.write("==============================\n\n")
                else:
                    # Manually write the packet info to the report file if the IP layer is not present
                    report_file.write(f"*Packet #{n}*\n")
                    report_file.write("IP Layer is not present\n")
                    report_file.write(f"{packet.summary()}\n\n")
                    report_file.write("==============================\n\n")

            except Exception as e:
                # Handle any other exceptions that may occur
                print(f"Error processing packet: {str(e)}")

        # Successful message
        print(f"Report generated successfully: {filename}")




# Entry point of the packet capture
if __name__ == '__main__':
    # Set the network interface for packet capturing
    interface = 'Ethernet'  

    # Set the number of packets to capture (0 for unlimited)
    num_packets = 10

    # Start capturing packets
    capture_packets(interface, num_packets)

    # Generate report 
    generate_report(captured_packets)
