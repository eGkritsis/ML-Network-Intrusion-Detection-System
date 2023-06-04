from capture.capture_packets import capture_packets
from capture.capture_packets import captured_packets
from anomaly_detection.detect_anomalies import detect_anomaly
from visualization.visualize import plot_anomaly_score, time_series_anomaly_plot


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
    anomaly_scores = detect_anomaly(captured_packets)

    # Produce a plot about anomaly scores
    plot_anomaly_score(anomaly_scores)

