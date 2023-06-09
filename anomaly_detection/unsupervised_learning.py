from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from pyod.models.iforest import IForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import os
from datetime import datetime


def extract_packet_info(packet):
    info = {}
    if IP in packet:
        info["Source IP"] = str(packet[IP].src)
        info["Destination IP"] = str(packet[IP].dst)
    else:
        info["Source IP"] = ""
        info["Destination IP"] = ""
    info["Protocol"] = packet[IP].proto if IP in packet else -1
    info["Packet Length"] = len(packet) if hasattr(packet, "__len__") else -1
    info["TTL"] = packet[IP].ttl if IP in packet else -1

    return info


def detect_anomaly(captured_packets):
    # Extract packet information
    dataset = []
    for packet in captured_packets:
        packet_info = extract_packet_info(packet)
        numeric_values = [float(value) for value in packet_info.values() if isinstance(value, (int, float))]
        dataset.append(numeric_values)

    # Convert the dataset to a numpy array
    dataset = np.array(dataset)

    # Initialize and fit the anomaly detection model
    model = IForest(contamination=0.01)  
    model.fit(dataset)

    # Calculate anomaly scores
    anomaly_scores = model.decision_function(dataset)

    # Detect anomalies in the dataset
    anomalies = model.predict(dataset)

    # Generate report 
    generate_report(captured_packets, anomalies)

    return anomaly_scores


def generate_report(captured_packets, anomalies):
    # Create a unique filename using the current date and time
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report_{timestamp}.txt"
    
    # Open the report file for writing
    with open(filename, 'w') as report_file:
        report_file.write("Network Traffic Report\n")
        report_file.write("==============================\n\n")

        try:
            # Anomalies counter
            counter = 0

            # Print the results
            for i, (packet, anomaly) in enumerate(zip(captured_packets, anomalies)):
                report_file.write(f"*Packet #{i+1}*\n")
                if hasattr(packet, 'time'):
                    report_file.write(f"Time Stamp: {packet.time}\n")
                report_file.write(f"{packet.summary()}\n")
                if TCP in packet:
                        report_file.write(f"Flags: {packet[TCP].flags}\n")
                if anomaly == 1:
                    counter = counter + 1
                    report_file.write("**Anomaly detected**\n\n")
                else:
                    report_file.write("Normal\n\n")
                report_file.write("==============================\n\n")
            
            report_file.write(f"TOTAL ANOMALIES FOUND: {counter}\n\n")
            report_file.write("==============================\n\n")

        except Exception as e:
                # Handle any other exceptions that may occur
                print(f"Error processing packet: {str(e)}")

        # Successful message
        print(f"Report generated successfully: {filename}\n")

    