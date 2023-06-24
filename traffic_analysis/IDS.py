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
    flow_info['FinFlagDist'] = calculate_flag_dist(flow, 'FIN')
    flow_info['SynFlagDist'] = calculate_flag_dist(flow, 'SYN')
    flow_info['RstFlagDist'] = calculate_flag_dist(flow, 'RST')
    flow_info['PshFlagDist'] = calculate_flag_dist(flow, 'PSH')
    flow_info['AckFlagDist'] = calculate_flag_dist(flow, 'ACK')
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
    flow_info['PktsIOratio'] = calculate_pkts_io_ratio(flow, count_spkts(flow), count_dpkts(flow))
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
    flow_info['NumCon'] = calculate_num_conversations(flow)
    flow_info['NumIPdst'] = calculate_num_unique_ipdst(flow)
    #flow_info['Start_flow'] = calculate_start_flow(flow)
    #flow_info['DeltaTimeFlow'] = calculate_delta_time_flow(flow)
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
    # Features {Ack, Syn, Fin, Psh, Rst}FlagDist: 
    # These features represent the distribution of TCP packets 
    # with specific TCP flags set (ACK, SYN, FIN, PSH, RST)

    flag_mapping = {
        'ACK': 0x10,
        'SYN': 0x02,
        'FIN': 0x01,
        'PSH': 0x08,
        'RST': 0x04
    }

    flag_dist = {}

    total_packets = len(flow['packets'])
    flag_count = 0
    
    # Count the occurrences of the flag
    for packet in flow['packets']:
        if 'tcp' in packet:
            tcp_packet = packet.tcp
            if hasattr(tcp_packet, 'flags'):
                flags_hex = int(tcp_packet.flags, 16)
                if flags_hex & flag_mapping[flag]:
                    flag_count += 1
            
    # Calculate the flag distribution as a percentage
    flag_dist[flag] = flag_count / total_packets if total_packets > 0 else 0.0

    return flag_dist[flag]

def calculate_protocol_over_ip(flow, protocol):
    #Features {TCP,UDP,DNS}OverIP: have been chosen since many attacks exploit specific
    #characteristics of these protocols. As an example, trojans and other remote access issue
    #a large number of DNS requests to locate their command and control server, so an high
    #DNSOverIP ratio may indicate malicious traffic

    protocol_count = sum(1 for packet in flow['packets'] if 'ip' in packet and packet.highest_layer == protocol)
    ip_count = sum(1 for packet in flow['packets'] if 'ip' in packet)
    return protocol_count / ip_count if ip_count != 0 else 0

def calculate_max_length(flow):
    # have been chosen since
    # packet number, size and inter-arrival times are useful to detect flooding-style attacks
    lengths = [int(packet.length) for packet in flow['packets']]
    return max(lengths) if lengths else 0.0

def calculate_min_length(flow):
    # have been chosen since
    # packet number, size and inter-arrival times are useful to detect flooding-style attacks
    lengths = [int(packet.length) for packet in flow['packets']]
    return min(lengths) if lengths else 0.0

def calculate_stddev_length(flow):
    # have been chosen since
    # packet number, size and inter-arrival times are useful to detect flooding-style attacks
    lengths = [len(packet) for packet in flow]
    if len(lengths) >= 2:
        return np.std(lengths)
    else:
        return float('nan')

def calculate_avg_length(flow):
    lengths = [len(packet) for packet in flow]
    if lengths:
        return sum(lengths) / len(lengths)
    else:
        return 0.0

def calculate_max_iat(flow):
    max_iat = 0.0
    prev_time = None

    for packet in flow['packets']:
        if 'time' in packet:
            curr_time = float(packet['time'])
            if prev_time is not None:
                iat = abs(curr_time - prev_time)
                max_iat = max(max_iat, iat)
            prev_time = curr_time

    return max_iat

def calculate_min_iat(flow):
    min_iat = float('inf')
    prev_time = None

    for packet in flow['packets']:
        if 'time' in packet:
            curr_time = float(packet['time'])
            if prev_time is not None:
                iat = curr_time - prev_time
                min_iat = min(min_iat, iat)
            prev_time = curr_time

    if min_iat == float('inf'):
        return 0.0

    return min_iat

def calculate_avg_iat(flow):
    iats = []
    prev_time = None

    for packet in flow['packets']:
        if 'time' in packet:
            curr_time = float(packet['time'])
            if prev_time is not None:
                iat = curr_time - prev_time
                iats.append(iat)
            prev_time = curr_time

    if len(iats) < 2:
        return 0.0

    avg_iat = sum(iats) / len(iats)
    return avg_iat

def calculate_avg_win_flow(flow):
    win_sizes = []
    for packet in flow['packets']:
        try:
            if 'tcp' in packet and 'window_size' in packet['tcp'].field_names:
                win_sizes.append(int(packet['tcp'].window_size))
        except AttributeError:
            pass
    if len(win_sizes) == 0:
        return 0
    return sum(win_sizes) / len(win_sizes)

def calculate_pkts_io_ratio(flow, spkts, dpkts):
    if spkts == 0 or dpkts == 0:
        return 0
    return spkts / dpkts

def calculate_first_pkt_length(flow):
    if len(flow['packets']) == 0:
        return 0

    first_packet = flow['packets'][0]
    if 'length' in first_packet:
        return int(first_packet['length'])
    else:
        return 0

def calculate_max_len_rx(flow):
    max_len_rx = 0
    for packet in flow['packets']:
        packet_length = int(packet.length)
        if packet_length > max_len_rx:
            max_len_rx = packet_length
    return max_len_rx

def calculate_min_len_rx(flow):
    min_len_rx = float('inf') 
    for packet in flow['packets']:
        packet_length = int(packet.length)
        if packet_length < min_len_rx:
            min_len_rx = packet_length
    return min_len_rx

def calculate_std_dev_len_rx(flow):
    lengths = [len(packet) for packet in flow['packets']]

    if len(lengths) < 2:
        return 0

    return statistics.stdev(lengths)

def calculate_avg_len_rx(flow):
    total_length = 0
    packet_count = 0

    for packet in flow['packets']:
        packet_length = int(packet.length)
        total_length += packet_length
        packet_count += 1

    if packet_count > 0:
        avg_len_rx = total_length / packet_count
    else:
        avg_len_rx = 0

    return avg_len_rx

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
    unique_ports = set()

    for packet in flow['packets']:
        try:
            destination_port = int(packet.tcp.dstport)
            unique_ports.add(destination_port)
        except AttributeError:
            # Skip packets without a TCP layer
            continue

    num_ports = len(unique_ports)
    return num_ports

def calculate_flow_len(flow):
    total_length = sum(int(packet.length) for packet in flow['packets'])
    return total_length

def calculate_flow_len_rx(flow):
    total_length = sum(int(packet.length) for packet in flow['packets'] if flow['destination_ip'] == '192.168.1.174') # Change to your own local IP address
    return total_length

def calculate_repeated_pkts_ratio(flow):
    packet_count = len(flow['packets'])
    unique_packets = set(packet.highest_layer for packet in flow['packets'])
    num_repeated_pkts = packet_count - len(unique_packets)
    repeated_pkts_ratio = num_repeated_pkts / packet_count if packet_count > 0 else 0.0
    return repeated_pkts_ratio

def calculate_num_conversations(flow):
    conversation_ids = set()
    for packet in flow['packets']:
        src_ip = flow['source_ip']
        dst_ip = flow['destination_ip']
        conversation_id = f"{src_ip}-{dst_ip}"
        conversation_ids.add(conversation_id)
    num_conversations = len(conversation_ids)
    return num_conversations

def calculate_num_unique_ipdst(flow):
    unique_ipdst = set()
    for packet in flow['packets']:
        dst_ip = flow['destination_ip']
        unique_ipdst.add(dst_ip)
    num_unique_ipdst = len(unique_ipdst)
    return num_unique_ipdst

def calculate_start_flow(flow):
    first_packet = flow['packets'][0]
    start_flow = first_packet.sniff_time
    return start_flow

def calculate_delta_time_flow(flow):
    packets = flow['packets']
    first_packet_time = packets[0].sniff_time
    last_packet_time = packets[-1].sniff_time
    delta_time_flow = last_packet_time - first_packet_time
    return delta_time_flow.total_seconds()

def calculate_http_packets(flow):
    http_packets = 0
    for packet in flow['packets']:
        if 'http' in packet:
            http_packets += 1
    return http_packets

def count_spkts(flow):
    spkts = 0
    for packet in flow['packets']:
        if 'ip' in packet and packet.ip.src == flow['source_ip']:
            spkts += 1
    return spkts

def count_dpkts(flow):
    dpkts = 0
    for packet in flow['packets']:
        if 'TCP' in packet or 'UDP' in packet:
            dpkts += 1
    return dpkts