from capture.capture_packets import capture_packets
from visualization.visualize import plot_anomaly_score, time_series_anomaly_plot
from anomaly_detection import detect_malicious_traffic
from anomaly_detection.detect_malicious_traffic import load_model, detection


# Entry point of the packet capture
if __name__ == '__main__':
    # Set the network interface for packet capturing 
    # 'Ethernet' or 'Wi-Fi'
    interface = 'Wi-Fi'  

    # Set the number of packets to capture (0 for unlimited)
    num_packets = 10

    # Start capturing packets
    captured_packets = capture_packets(interface, num_packets)

    # Detect anomalies and generate report
    #anomaly_scores = detect_anomaly(captured_packets)

    # Produce a plot about anomaly scores
    #plot_anomaly_score(anomaly_scores)

    # Model file
    model_file = r'D:\AUEB\Projects\Network-Traffic-Analyzer\model.pkl'

    # Load model
    model = load_model(model_file)

    # Detect anomalies and generate report
    predicted_labels = detection(captured_packets, model)
    generate_report(predicted_labels)

    