from capture.capture_traffic import capture_flows
from traffic_analysis.IDS import load_model, supervised_flow_detection, generate_report_attack_cat, unsupervised_flow_detection


def main():
    # Set the network interface for packet capturing 
    # 'Ethernet' or 'Wi-Fi' or 'Adapter for loopback traffic capture'
    interface = 'Wi-fi'  

    # Set the target IP or the range of IP addresses you want to capture traffic from
    target_ip = get_local_ip()

    # Set the display filter
    filter = f'ip.addr=={target_ip}'

    # Start capturing flows
    captured_flows = capture_flows(interface, filter)

    # Model file 
    model_file = r'rf_attack_cat_mapped.pkl'

    # Load model
    model = load_model(model_file)

    # Detect malicious traffic
    predicted_labels = supervised_flow_detection(captured_flows, model)

    # Generate report (Target = attack_cat)
    generate_report_attack_cat(predicted_labels)

    # UNSUPERVISED LEARNING
    unsupervised_flow_detection(captured_flows)


# Entry point of the packet capture
if __name__ == '__main__':
    main()
    

    