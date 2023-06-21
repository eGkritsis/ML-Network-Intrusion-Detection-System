import pandas as pd
import joblib
from datetime import datetime
import numpy as np
from sklearn.impute import SimpleImputer
from collections import Counter
import statistics


# Extract and preprocess the necessary information from each flow of packets
def extract_flow_info(flow, id):
    # Calculate timestamps
    timestamps = [datetime.timestamp(packet.sniff_time) for packet in flow['packets']]

    flow_extra_info = {}

    flow_extra_info['source_ip'] = flow['source_ip']
    flow_extra_info['destination_ip'] = flow['destination_ip']
    flow_extra_info['source_port'] = flow['source_port']
    flow_extra_info['destination_port'] = flow['destination_port']

    
    flow_info = {}
    flow_info['FinFlagDist'] = calculate_flag_dist(flow, 'Finflag')
    flow_info['SynFlagDist'] = calculate_flag_dist(flow, 'SynFlag')
    flow_info['RstFlagDist'] = calculate_flag_dist(flow, 'RstFlag')
    flow_info['PshFlagDist'] = calculate_flag_dist(flow, 'PshFlag')
    flow_info['AckFlagDist'] = calculate_flag_dist(flow, 'AckFlag')
    flow_info['DNSoverIP'] = calculate_protocol_over_ip(flow, 'DNS')
    flow_info['TCPoverIP'] = calculate_protocol_over_ip(flow, 'TCP')
    flow_info['UDPoverIP'] = calculate_protocol_over_ip(flow, 'UDP')
    flow_info['MaxLen'] = calculate_max_length(flow)
    flow_info['MinLen'] = calculate_min_length(flow)
    flow_info['StdDevLen'] = calculate_stddev_length(flow)
    flow_info['AvgLen'] = calculate_avg_length(flow)
    flow_info['MaxIAT'] = calculate_max_iat(flow)
    flow_info['MinIAT'] = calculate_min_iat(flow)
    flow_info['AvgIAT'] = calculate_avg_iat(flow)
    flow_info['AvgWinFlow'] = calculate_avg_win_flow(flow)
    flow_info['PktsIOratio'] = calculate_pkts_io_ratio(flow)
    flow_info['1stPktLen'] = calculate_first_pkt_length(flow)
    flow_info['MaxLenrx'] = calculate_max_len_rx(flow)
    flow_info['MinLenrx'] = calculate_min_len_rx(flow)
    flow_info['StdDevLenrx'] = calculate_std_dev_len_rx(flow)
    flow_info['AvgLenrx'] = calculate_avg_len_rx(flow)
    flow_info['MinIATrx'] = calculate_min_iat_rx(flow, timestamps)
    flow_info['AvgIATrx'] = calculate_avg_iat_rx(flow, timestamps)
    flow_info['NumPorts'] = calculate_num_ports(flow)
    flow_info['FlowLEN'] = calculate_flow_len(flow)
    flow_info['FlowLENrx'] = calculate_flow_len_rx(flow)
    flow_info['repeated_pkts_ratio'] = calculate_repeated_pkts_ratio(flow)
    flow_info['NumCon'] = calculate_num_conversations(flow, flows)
    flow_info['NumIPdst'] = calculate_num_unique_ipdst(flow, flows)
    flow_info['Start_flow'] = calculate_start_flow(flow, flows)
    flow_info['DeltaTimeFlow'] = calculate_delta_time_flow(flow)
    flow_info['HTTPpkts'] = calculate_http_packets(flow)
            

    print(f"id: {id}")
    print(flow_extra_info)
    print(flow_info)
    print("----------------------------------------------------------------------------------------------------------------------------------------------------")

    return flow_info

# ------------------------------ SUPERVISED LEARNING -----------------------------------------------------------------------------

def supervised_flow_detection(captured_flows, model):
    # Detect anomalies using the model provided

    # List to store the extracted features of the flow
    flow_info = []
    n = 0

    # Extract flow info for each captured flow
    for flow in captured_flows:
        n += 1
        info = extract_flow_info(flow, n)
        flow_info.append(info)

    # Create an instance of SimpleImputer with a strategy to fill missing values with the mean
    imputer = SimpleImputer(strategy='mean')
    flow_info_df = pd.DataFrame(flow_info)
    flow_info_df = imputer.fit_transform(flow_info_df)
    
    # Check if the DataFrame has zero samples
    if flow_info_df.shape[0] == 0:
        # No valid samples
        return None

    # Use the model to predict labels for the preprocessed flows
    predicted_labels = detect_anomaly(flow_info_df, model)

    return predicted_labels

def detect_anomaly(info, model):
    predicted_labels = model.predict(info)
    return predicted_labels

# Load the trained Random Forest model
def load_model(model_file):
    model = joblib.load(model_file)
    return model

def generate_report_label(predicted_labels):
    # Generate report based on the predicted labels
    normal_count = np.count_nonzero(predicted_labels == 0)
    malicious_count = np.count_nonzero(predicted_labels == 1)

    print()
    print("Flow Report:")
    print("-------------------------")
    for i, label in enumerate(predicted_labels):
        print(f"Flow {i+1}: {'Malicious' if label == 1 else 'Normal'}")
        print("-------------------------")
    print()
    print(f"Number of normal flows: {normal_count}")
    print(f"Number of malicious flows: {malicious_count}")
    print("Generate report complete.")

# --------------------------------- FLOW'S INFORMATON CALCULATION FUNCTIONS -----------------------------------------------------

def calculate_flag_dist(flow, flag):
    flags = []
    for packet in flow['packets']:
        if 'tcp' in packet:
            tcp_packet = packet.tcp
            if hasattr(tcp_packet, flag.lower()):
                flags.append(getattr(tcp_packet, flag.lower()))
            else:
                flags.append(0)
        else:
            flags.append(0)
    flag_dist = {f: flags.count(f) for f in set(flags)}
    return flag_dist

def calculate_protocol_over_ip(flow, protocol):
    protocol_count = sum(1 for packet in flow['packets'] if 'ip' in packet and packet.highest_layer == protocol)
    ip_count = sum(1 for packet in flow['packets'] if 'ip' in packet)
    return protocol_count / ip_count if ip_count != 0 else 0

def calculate_max_length(flow):
    lengths = [int(packet.length) for packet in flow['packets']]
    return max(lengths) if lengths else 0

def calculate_min_length(flow):
    lengths = [int(packet.length) for packet in flow['packets']]
    return min(lengths) if lengths else 0

def calculate_stddev_length(flow):
    lengths = []
    for packet in flow['packets']:
        try:
            length = int(packet['length'])
            lengths.append(length)
        except KeyError:
            pass
    return np.std(lengths)

def calculate_avg_length(flow):
    lengths = []
    for packet in flow['packets']:
        try:
            length = int(packet['length'])
            lengths.append(length)
        except KeyError:
            pass
    return np.mean(lengths)

def calculate_max_iat(flow):
    max_iat = 0.0
    prev_time = None
    
    for i in range(1, len(flow['packets'])):
        if 'time' in flow['packets'][i] and 'time' in flow['packets'][i-1]:
            iat = abs(float(flow['packets'][i]['time']) - float(flow['packets'][i-1]['time']))
            max_iat = max(max_iat, iat)

    return max_iat

def calculate_min_iat(flow):
    if len(flow['packets']) <= 1:
        return 0

    iats = []
    for i in range(1, len(flow['packets'])):
        packet = flow['packets'][i]
        previous_packet = flow['packets'][i-1]

        if 'time' in packet and 'time' in previous_packet:
            iat = float(packet['time']) - float(previous_packet['time'])
            iats.append(iat)

    if iats:
        min_iat = min(iats)
        return min_iat
    else:
        return 0

def calculate_avg_iat(flow):
    iats = [float(flow['packets'][i]['time']) - float(flow['packets'][i-1]['time']) for i in range(1, len(flow['packets']))]
    return statistics.mean(iats) if iats else 0

def calculate_avg_win_flow(flow):
    if len(flow['packets']) == 0:
        return 0
    win_sizes = [packet.tcp.window_size for packet in flow['packets'] if 'tcp' in packet and hasattr(packet.tcp, 'window_size')]
    if len(win_sizes) == 0:
        return 0
    return sum(win_sizes) / len(win_sizes)

def calculate_pkts_io_ratio(flow):
    if flow_info['spkts'] == 0 or flow_info['dpkts'] == 0:
        return 0
    return flow_info['spkts'] / flow_info['dpkts']

def calculate_first_pkt_length(flow):
    if len(flow['packets']) == 0:
        return 0
    return len(flow['packets'][0].payload)

def calculate_max_len_rx(flow):
    if len(flow['packets']) == 0:
        return 0
    return max(len(packet.payload) for packet in flow['packets'])

def calculate_min_len_rx(flow):
    if len(flow['packets']) == 0:
        return 0
    return min(len(packet.payload) for packet in flow['packets'])

def calculate_std_dev_len_rx(flow):
    if len(flow['packets']) == 0:
        return 0
    lengths = [len(packet.payload) for packet in flow['packets']]
    return statistics.stdev(lengths)

def calculate_avg_len_rx(flow):
    if len(flow['packets']) == 0:
        return 0
    lengths = [len(packet.payload) for packet in flow['packets']]
    return statistics.mean(lengths)

def calculate_min_iat_rx(flow, timestamps):
    if len(timestamps) <= 1:
        return 0
    iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    return min(iats)

def calculate_avg_iat_rx(flow, timestamps):
    if len(timestamps) <= 1:
        return 0
    iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    return statistics.mean(iats)

def calculate_num_ports(flow):
    return len(set(packet.destination_port for packet in flow['packets']))

def calculate_flow_len(flow):
    return sum(len(packet) for packet in flow['packets'])

def calculate_flow_len_rx(flow):
    return sum(len(packet) for packet in flow['packets'] if packet.destination_ip == flow['destination_ip'])

def calculate_repeated_pkts_ratio(flow):
    unique_pkts = set(packet.packet_id for packet in flow['packets'])
    total_pkts = len(flow['packets'])
    repeated_pkts = total_pkts - len(unique_pkts)
    return repeated_pkts / total_pkts if total_pkts != 0 else 0

def calculate_num_conversations(flow, flows):
    source_ip = flow['source_ip']
    destination_ip = flow['destination_ip']
    
    num_conversations = sum(1 for f in flows if (f['source_ip'] == source_ip and f['destination_ip'] == destination_ip) or (f['source_ip'] == destination_ip and f['destination_ip'] == source_ip))
    return num_conversations

def calculate_num_unique_ipdst(flow, flows):
    destination_ips = set(f['destination_ip'] for f in flows)
    num_unique_ipdst = len(destination_ips)
    return num_unique_ipdst

def calculate_start_flow(flow, flows):
    sorted_flows = sorted(flows, key=lambda f: f['start_time'])
    start_flow = sorted_flows[0]['start_time'] if sorted_flows else 0
    return start_flow

def calculate_delta_time_flow(flow):
    timestamps = [datetime.timestamp(packet.sniff_time) for packet in flow['packets']]
    delta_time_flow = max(timestamps) - min(timestamps) if len(timestamps) > 0 else 0
    return delta_time_flow

def calculate_http_packets(flow):
    http_packets = sum(1 for packet in flow['packets'] if 'http' in packet)
    return http_packets
