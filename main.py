from capture.capture_traffic import capture_packets, capture_flows
from visualization.visualize import plot_anomaly_score, time_series_anomaly_plot
from anomaly_detection import supervised_learning, unsupervised_learning
from anomaly_detection.supervised_learning import load_model, flow_detection, packet_detection, generate_report

# Tha doume einai gia to unsupervised isws fugei
from anomaly_detection.unsupervised_learning import detect_anomaly    



# Entry point of the packet capture
if __name__ == '__main__':
    # Set the network interface for packet capturing 
    # 'Ethernet' or 'Wi-Fi'
    interface = 'Wi-Fi'  

    # Set the number of packets to capture (0 for unlimited)
    num_packets = 100

    # Start capturing packets
    #captured_packets = capture_packets(interface, num_packets)

    # Detect anomalies and generate report
    #anomaly_scores = detect_anomaly(captured_packets)

    # Produce a plot about anomaly scores
    #plot_anomaly_score(anomaly_scores)

    # Start capturing flows
    captured_flows = capture_flows(interface, num_packets)

    # Model file
    model_file = r'\Network-Traffic-Analyzer\model.pkl'

    # Load model
    model = load_model(model_file)

    # Detect anomalies and generate report
    predicted_labels = flow_detection(captured_flows, model)
    generate_report(predicted_labels)

    