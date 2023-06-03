import os
from datetime import datetime

def generate_report(captured_packets):
    # Create a unique filename using the current date and time
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report_{timestamp}.txt"

    # Open the report file for writing
    with open(filename, 'w') as report_file:
        report_file.write("Network Traffic Report\n")
        report_file.write("======================\n\n")

        # Iterate over the captured packet data
        for packet in captured_packets:
            # Extract information from the packet
            source_ip = packet.get("IP").src
            destination_ip = packet.get("IP").dst
            source_port = packet.get("TCP").sport
            destination_port = packet.get("TCP").dport
            packet_size = len(packet)

            # Write the extracted information to the report file
            report_file.write(f"Source IP: {source_ip}\n")
            report_file.write(f"Destination IP: {destination_ip}\n")
            report_file.write(f"Source Port: {source_port}\n")
            report_file.write(f"Destination Port: {destination_port}\n")
            report_file.write(f"Packet Size: {packet_size} bytes\n")
            report_file.write("==============================\n\n")

            # Successful message
            print(f"Report generated successfully: {filename}")
