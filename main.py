from capture.capture_traffic import capture_flows
from anomaly_detection.supervised_learning import load_model, flow_detection, generate_report_label, generate_report_label_attack_cat,generate_report_attack_cat  

def main():
    # Set the network interface for packet capturing 
    # 'Ethernet' or 'Wi-Fi'
    interface = 'Ethernet'  

    # Set the number of packets to capture (0 for unlimited)
    num_packets = 1000
    # Start capturing packets
    #captured_packets = capture_packets(interface, num_packets)

    # Detect anomalies and generate report
    #anomaly_scores = detect_anomaly(captured_packets)

    # Produce a plot about anomaly scores
    #plot_anomaly_score(anomaly_scores)

    # Start capturing flows
    captured_flows = capture_flows(interface, num_packets)

    # Model file (Target = label)
    #model_file = r'model_label.pkl'

    # Model file (Target = attack_cat)
    #model_file = r'model_cat.pkl'

    # Model file (Targets = label + attack_cat)
    #model_file = r'model_label_attack_cat.pkl'

    # Model file (Targets = label - NAIVE BAYES)
    #model_file = r'naive_label.pkl'

    # Model file (Targets = label - MLP)
    #model_file = r'mlp_label.pkl'

    # Model fie (Targets = label - GBC)
    model_file = r'gbc_training.pkl'

    # Load model
    model = load_model(model_file)

    # Detect malicious traffic
    predicted_labels = flow_detection(captured_flows, model)

    # Generate report (Target = label)
    generate_report_label(predicted_labels)

    # Generate report (Target = attack_cat)
    #generate_report_attack_cat(predicted_labels)

    # Generate report (Target = label + attack_cat)
    #generate_report_label_attack_cat(predicted_labels)


# Entry point of the packet capture
if __name__ == '__main__':
    main()
    

    