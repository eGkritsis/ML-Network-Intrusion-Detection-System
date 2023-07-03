from capture.capture_traffic import capture_flows
from traffic_analysis.IDS import load_model, supervised_flow_detection, generate_report_label
from traffic_analysis.IDS import get_local_ip

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
    model_file = r'rf_kdd.pkl'

    # Load model
    model = load_model(model_file)

    # Detect malicious traffic
    predicted_labels = supervised_flow_detection(captured_flows, model)

    # Generate report (Target = label)
    generate_report_label(predicted_labels)

# Entry point of the packet capture
if __name__ == '__main__':
    main()
    

