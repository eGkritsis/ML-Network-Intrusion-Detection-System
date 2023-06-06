from scapy.layers.inet import IP, TCP, UDP
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import joblib


def extract_packet_info2(packet):
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
    info["ackdat"] = 0  # Placeholder value for the missing feature "ackdat"
    info["attack_cat"] = ""  # Placeholder value for the missing feature "attack_cat"
    info["ct_dst_ltm"] = 0  # Placeholder value for the missing feature "ct_dst_ltm"
    # Add the missing features with appropriate placeholder values

    return info


def extract_packet_info(packet, id):
    # Implement the function to preprocess the captured packets
    # Convert the packets into a DataFrame with the same column names and data types as the training data
    # Returns the preprocessed data

    packet_info = {}

    
    # Extract packet information
    packet_info['id'] = id
    packet_info['dur'] = packet.time
    packet_info['proto'] = '-'
    packet_info['service'] = '-'  
    packet_info['state'] = '-'  
    packet_info['spkts'] = 0
    packet_info['dpkts'] = 0
    packet_info['sbytes'] = len(packet)
    packet_info['dbytes'] = 0
    packet_info['rate'] = 0
    packet_info['sttl'] = 0
    packet_info['dttl'] = 0
    packet_info['sload'] = 0
    packet_info['dload'] = 0
    packet_info['sloss'] = 0
    packet_info['dloss'] = 0
    packet_info['sinpkt'] = 0
    packet_info['dinpkt'] = 0
    packet_info['sjit'] = 0
    packet_info['djit'] = 0
    packet_info['swin'] = 0
    packet_info['stcpb'] = 0
    packet_info['dtcpb'] = 0
    packet_info['dwin'] = 0
    packet_info['tcprtt'] = 0
    packet_info['synack'] = 0
    packet_info['ackdat'] = 0
    packet_info['smean'] = 0
    packet_info['dmean'] = 0
    packet_info['trans_depth'] = 0
    packet_info['response_body_len'] = 0
    packet_info['ct_srv_src'] = 0
    packet_info['ct_state_ttl'] = 0
    packet_info['ct_dst_ltm'] = 0
    packet_info['ct_src_dport_ltm'] = 0
    packet_info['ct_dst_sport_ltm'] = 0
    packet_info['ct_dst_src_ltm'] = 0
    packet_info['is_ftp_login'] = 0
    packet_info['ct_ftp_cmd'] = 0
    packet_info['ct_flw_http_mthd'] = 0
    packet_info['ct_src_ltm'] = 0
    packet_info['ct_srv_dst'] = 0
    packet_info['is_sm_ips_ports'] = 0
    packet_info['attack_cat'] = 'unknown'
    

    try:
        # Calculate features
        if packet.haslayer(IP):
            ip = packet[IP]
            packet_info['spkts'] = ip.len
            packet_info['dpkts'] = 0  # Placeholder for dpkts, you can replace it with the actual value
            packet_info['sbytes'] = ip.len
            packet_info['dbytes'] = 0  # Placeholder for dbytes, you can replace it with the actual value
            packet_info['sttl'] = ip.ttl
            packet_info['dttl'] = 0  # Placeholder for dttl, you can replace it with the actual value

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_info['proto'] = 'tcp'
            packet_info['rate'] = 0  # Placeholder for rate, you can replace it with the actual value
            packet_info['sload'] = 0  # Placeholder for sload, you can replace it with the actual value
            packet_info['dload'] = 0  # Placeholder for dload, you can replace it with the actual value
            packet_info['sinpkt'] = 0  # Placeholder for sinpkt, you can replace it with the actual value
            packet_info['dinpkt'] = 0  # Placeholder for dinpkt, you can replace it with the actual value
            packet_info['swin'] = tcp.window
            packet_info['stcpb'] = tcp.seq
            packet_info['dtcpb'] = 0  # Placeholder for dtcpb, you can replace it with the actual value
            packet_info['dwin'] = 0  # Placeholder for dwin, you can replace it with the actual value
            packet_info['tcprtt'] = 0  # Placeholder for tcprtt, you can replace it with the actual value
            packet_info['synack'] = 0  # Placeholder for synack, you can replace it with the actual value
            packet_info['ackdat'] = 0  # Placeholder for ackdat, you can replace it with the actual value
            packet_info['smean'] = 0  # Placeholder for smean, you can replace it with the actual value
            packet_info['dmean'] = 0  # Placeholder for dmean, you can replace it with the actual value

        if packet.haslayer(UDP):
            udp = packet[UDP]
            packet_info['proto'] = 'udp'
            packet_info['rate'] = 0  # Placeholder for rate, you can replace it with the actual value
            packet_info['sload'] = 0  # Placeholder for sload, you can replace it with the actual value
            packet_info['dload'] = 0  # Placeholder for dload, you can replace it with the actual value
            packet_info['sinpkt'] = 0  # Placeholder for sinpkt, you can replace it with the actual value
            packet_info['dinpkt'] = 0  # Placeholder for dinpkt, you can replace it with the actual value

    except Exception as e:
        print(f"Error extracting packet info: {e}")

    '''
    # Calculate rate
    if packet_info['dur'] != 0:
        packet_info['rate'] = (packet_info['spkts'] + packet_info['dpkts']) / packet_info['dur']

    # Calculate sinpkt and dinpkt
    if packet_info['spkts'] > 1:
        packet_info['sinpkt'] = packet_info['dur'] / (packet_info['spkts'] - 1)
    if packet_info['dpkts'] > 0:
        packet_info['dinpkt'] = packet_info['dur'] / packet_info['dpkts']

    # Calculate smean and dmean
    if packet_info['spkts'] > 0:
        packet_info['smean'] = packet_info['sbytes'] / packet_info['spkts']
    if packet_info['dpkts'] > 0:
        packet_info['dmean'] = packet_info['dbytes'] / packet_info['dpkts']
   '''

    return packet_info
    

def detection(captured_packets, model):
    # Detect anomalies using the Random Forest model provided
    # Uses the loaded model to predict the labels for the preprocessed packets
    # Return the predicted labels

    # List to store the extracted features of the packet
    packet_info = []
    n = 0

    # Extract packet info for each captured packet
    for packet in captured_packets:
        n = n + 1
        info = extract_packet_info(packet, n)
        packet_info.append(info)

    packet_info_df = pd.DataFrame(packet_info)

    # Load trained random forest model
    #model = load_model(model_file)

    # use the model to predict labels for the preprocessed packets
    predicted_labels = detect_anomaly(packet_info_df, model)

    return predicted_labels

def detect_anomaly(packet_info, model):
    predicted_labels = model.predict(packet_info)

    return predicted_labels

# Load the trained Random Forest model
def load_model(model_file):
    # Implement the function to load the trained Random Forest model from the saved file
    # Return the loaded model
    model = joblib.load('model.pkl')
    return model

def generate_report(predicted_labels):
    # Implement the function to generate a report based on the predicted labels
    # Summarize the detection results, such as the number of normal packets, malicious packets, etc.
    # Print or save the report as per your requirements
    normal_count = predicted_labels.count(0)
    malicious_count = predicted_labels.count(1)
    print(f"Number of normal packets: {normal_count}")
    print(f"Number of malicious packets: {malicious_count}")
    print("Generate report complete.")



