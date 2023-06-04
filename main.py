from capture.capture_packets import capture_packets
from capture.capture_packets import captured_packets
from anomaly_detection.detect_anomalies import detect_anomaly


# Entry point of the packet capture
if __name__ == '__main__':
    # Set the network interface for packet capturing 
    # 'Ethernet' or 'Wi-Fi'
    interface = 'Wi-Fi'  

    # Set the number of packets to capture (0 for unlimited)
    num_packets = 100

    # Start capturing packets
    capture_packets(interface, num_packets)
 
    # Detect anomalies and generate report
    detect_anomaly(captured_packets)


