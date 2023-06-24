from capture.capture_traffic import capture_flows
from traffic_analysis.IDS import load_model, supervised_flow_detection, generate_report_label

def main():
    # Set the network interface for packet capturing 
    # 'Ethernet' or 'Wi-Fi'
    interface = 'Wi-fi'  

    # Set the number of packets to capture 
    num_packets = 300

    # Start capturing flows
    captured_flows = capture_flows(interface, num_packets)

    # Model file 
    model_file = r'rf_31_kdd.pkl'

    # Load model
    model = load_model(model_file)

    # Detect malicious traffic
    predicted_labels = supervised_flow_detection(captured_flows, model)

    # Generate report (Target = label)
    generate_report_label(predicted_labels)

    # UNSUPERVISED LEARNING
    #unsupervised_flow_detection(captured_flows)

    #plot_attack_categories(predicted_labels)


# Entry point of the packet capture
if __name__ == '__main__':
    main()
    

    