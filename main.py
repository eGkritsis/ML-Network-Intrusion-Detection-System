from capture.capture_traffic import capture_flows
from traffic_analysis.IDS import load_model, supervised_flow_detection, generate_report_label, generate_report_label_attack_cat, generate_report_attack_cat, generate_anomaly_report, unsupervised_flow_detection


def main():
    # Set the network interface for packet capturing 
    # 'Ethernet' or 'Wi-Fi'
    interface = 'Wi-fi'  

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

    # Model file 
    model_file = r'rf_attack_cat_mapped.pkl'

    # Load model
    model = load_model(model_file)

    # Detect malicious traffic
    predicted_labels = supervised_flow_detection(captured_flows, model)

    # Generate report (Target = label)
    #generate_report_label(predicted_labels)

    # Generate report (Target = attack_cat)
    generate_report_attack_cat(predicted_labels)

    # Generate report (Target = label + attack_cat)
    #generate_report_label_attack_cat(predicted_labels)

    # UNSUPERVISED LEARNING
    unsupervised_flow_detection(captured_flows)


# Entry point of the packet capture
if __name__ == '__main__':
    main()
    

    