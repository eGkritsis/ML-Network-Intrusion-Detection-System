from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
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

    '''
    # Protocol number to name mapping (50 most common)
    protocol_mapping = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        89: "OSPF",
        132: "SCTP",
        136: "UDPLite",
        255: "Reserved",
        3306: "MySQL",
        3389: "RDP",
        5353: "mDNS",
        5632: "PCAnywhere",
        5060: "SIP",
        5061: "SIP-TLS",
        5900: "VNC",
        5938: "TeamViewer",
        8888: "Sun Answerbook",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        445: "SMB",
        500: "ISAKMP",
        1433: "MSSQL",
        1434: "MSSQL Monitor",
        1521: "Oracle",
        1701: "L2TP",
        1723: "PPTP",
        1812: "RADIUS",
        1813: "RADIUS Accounting",
        1900: "SSDP",
        2049: "NFS",
        2222: "DirectAdmin",
        2375: "Docker",
        3128: "HTTP Proxy",
        3306: "MySQL",
        3389: "RDP",
        5060: "SIP",
        5061: "SIP-TLS",
        5432: "PostgreSQL",
        5500: "VNC",
        5800: "VNC HTTP",
        5900: "VNC",
        5901: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS",
        8888: "Sun Answerbook",
        9001: "Tor",
        9100: "Printer",
        9200: "Elasticsearch",
        9300: "Elasticsearch",
        9418: "Git",
        9999: "Telnet",
        10000: "Webmin"
    }
    '''

    # Open the report file for writing
    with open(filename, 'w') as report_file:
        report_file.write("Network Traffic Report\n\n")
        report_file.write("==============================\n\n")

        # Iterate over the captured packet data
        for packet in captured_packets:
            # Increase packet number
            n = n + 1
            try:
                '''
                # Check if the packet has the IP layer
                if packet.haslayer(IP):
                    # Extract information from the packet
                    source_ip = packet[IP].src
                    destination_ip = packet[IP].dst
                    source_port = packet[TCP].sport
                    destination_port = packet[TCP].dport
                    protocol_number = packet[IP].proto
                    protocol = protocol_mapping.get(protocol_number, "Unknown")
                    packet_size = len(packet)

                    # Write the extracted information to the report file
                    report_file.write(f"*Packet #{n}*\n")
                    report_file.write(f"Source IP: {source_ip}\n")
                    report_file.write(f"Destination IP: {destination_ip}\n")
                    report_file.write(f"Source Port: {source_port}\n")
                    report_file.write(f"Destination Port: {destination_port}\n")
                    report_file.write(f"Protocol: {protocol}\n")
                    report_file.write(f"Packet Size: {packet_size} bytes\n")
                    report_file.write(f"{packet.summary()}\n\n")
                    report_file.write("==============================\n\n")
                
                else:
                    # Manually write the packet info to the report file if the IP layer is not present
                    report_file.write(f"*Packet #{n}*\n")
                    report_file.write("IP Layer is not present\n")
                    report_file.write(f"{packet.summary()}\n\n")
                    report_file.write("==============================\n\n") 
                '''

                report_file.write(f"*Packet #{n}*\n")
                if hasattr(packet, 'time'):
                    report_file.write(f"Time Stamp: {packet.time}\n")
                report_file.write(f"{packet.summary()}\n")
                if TCP in packet:
                        report_file.write(f"Flags: {packet[TCP].flags}\n\n")
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
    num_packets = 0

    # Start capturing packets
    capture_packets(interface, num_packets)

    # Generate report 
    generate_report(captured_packets)
