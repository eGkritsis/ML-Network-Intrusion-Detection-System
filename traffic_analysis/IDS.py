from sklearn.experimental import enable_iterative_imputer
from sklearn.preprocessing import PowerTransformer
from sklearn.impute import IterativeImputer
from sklearn.impute import SimpleImputer
from collections import Counter
from datetime import datetime
import pandas as pd
import configparser
import numpy as np
import statistics
import requests
import joblib
import socket



# Extract and preprocess the necessary information from each flow of packets
def extract_flow_info(flow, id):
    # Calculate timestamps
    timestamps = [datetime.timestamp(packet.sniff_time) for packet in flow['packets']]

    flow_extra_info = {}

    flow_extra_info['source_ip'] = flow['source_ip']
    flow_extra_info['destination_ip'] = flow['destination_ip']
    flow_extra_info['source_port'] = flow['source_port']
    flow_extra_info['destination_port'] = flow['destination_port']
    flow_extra_info['Number of packets'] = len(flow['packets'])

    
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
    flow_info['MaxIAT'] = calculate_max_iat(flow, timestamps)
    flow_info['MinIAT'] = calculate_min_iat(flow, timestamps)
    flow_info['AvgIAT'] = calculate_avg_iat(flow, timestamps)
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
    flow_info['NumCon'] = calculate_num_connections(flow)
    flow_info['NumIPdst'] = calculate_num_unique_ipdst(flow)
    #flow_info['Start_flow'] = calculate_start_flow(timestamps)
    #flow_info['DeltaTimeFlow'] = calculate_delta_time_flow(timestamps)
    flow_info['HTTPpkts'] = calculate_http_packets(flow)

    print(f"Flow: {id}\n")

    print("Flow's basic information:")
    print(flow_extra_info)
    print()

    
    # Check IP reputation
    if flow_extra_info['destination_ip'] != get_local_ip():
        reputation = check_ip_reputation(flow_extra_info['destination_ip'])
        if reputation is not None:
            print(f"AbuseIPDB Reputation: {reputation}")
        else:
            print(f"Failed to retrieve IP reputation from AbuseIPDB")
    else:
        reputation = check_ip_reputation(flow_extra_info['source_ip'])
        if reputation is not None:
            print(f"AbuseIPDB Reputation: {reputation}")
        else:
            print(f"Failed to retrieve IP reputation from AbuseIPDB")


    print()
    print("Flow's features:")
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
        info= extract_flow_info(flow, n)
        flow_info.append(info)

    flow_info_df = pd.DataFrame(flow_info)

    # Check if the DataFrame has zero samples
    if flow_info_df.shape[0] == 0:
        # No valid samples
        return None
    
    # Apply MICE imputation
    imputer = IterativeImputer()
    flow_info_df = imputer.fit_transform(flow_info_df)

    # Apply PowerTransformer scaling
    scaler = PowerTransformer()
    scaled_data = scaler.fit_transform(flow_info_df)

    # Use the model to predict labels for the preprocessed flows
    predicted_labels = detect_anomaly(scaled_data, model) 

    return predicted_labels

def detect_anomaly(info, model):
    predicted_labels = model.predict(info)
    return predicted_labels

# Load the trained Random Forest model
def load_model(model_file):
    model = joblib.load(model_file)
    return model

def check_ip_reputation(ip_address):
    api_key = get_api_key()
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=30"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None

def get_api_key():
    config = configparser.ConfigParser()
    config.read(r'..\Network-Traffic-Analyzer\traffic_analysis\config.ini')
    api_key = config.get('API', 'Key')
    return api_key

def generate_report_label(predicted_labels):
    # Generate report based on the predicted labels
    normal_count = np.count_nonzero(predicted_labels == 0)
    malicious_count = np.count_nonzero(predicted_labels == 1)

    if predicted_labels is None:
        print("No predicted labels available.")
        return

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
    flag_count = 0.0
    
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
    # Features {TCP,UDP,DNS}OverIP: have been chosen since many attacks exploit specific
    # characteristics of these protocols. As an example, trojans and other remote access issue
    # a large number of DNS requests to locate their command and control server, so an high
    # DNSOverIP ratio may indicate malicious traffic

    protocol_count = sum(1 for packet in flow['packets'] if 'ip' in packet and packet.highest_layer == protocol)
    ip_count = sum(1 for packet in flow['packets'] if 'ip' in packet)
    return protocol_count / ip_count if ip_count != 0 else 0.0

def calculate_max_length(flow):
    lengths = [int(packet.length) for packet in flow['packets']]
    return float(max(lengths)) if lengths else 0.0

def calculate_min_length(flow):
    lengths = [int(packet.length) for packet in flow['packets']]
    return float(min(lengths)) if lengths else 0.0

def calculate_stddev_length(flow):
    lengths = [len(packet) for packet in flow]
    if len(lengths) >= 2:
        return np.std(lengths)
    else:
        return 0.0

def calculate_avg_length(flow):
    total_length = 0
    num_packets = len(flow['packets'])

    for packet in flow['packets']:
        total_length = total_length + len(packet) 
    
    if num_packets > 0:
        avg_length = total_length / num_packets
    else:
        avg_length = 0.0
    
    return avg_length

def calculate_max_iat(flow, timestamps):
    max_iat = 0.0

    for i in range(1, len(timestamps)):
        iat = timestamps[i] - timestamps[i-1]
        max_iat = max(max_iat, iat)

    return float(max_iat)

def calculate_min_iat(flow, timestamps):
    if len(timestamps) <= 1:
        return 0.0

    iats = []
    for i in range(1, len(timestamps)):
        iat = timestamps[i] - timestamps[i-1]
        iats.append(iat)

    min_iat = min(iats)
    return float(min_iat)

def calculate_avg_iat(flow, timestamps):
    if len(timestamps) <= 1:
        return 0.0

    iats = []
    for i in range(1, len(timestamps)):
        iat = timestamps[i] - timestamps[i-1]
        iats.append(iat)

    avg_iat = sum(iats) / len(iats)
    return float(avg_iat)

def calculate_avg_win_flow(flow):
    win_sizes = []
    for packet in flow['packets']:
        try:
            if 'tcp' in packet and 'window_size' in packet['tcp'].field_names:
                win_sizes.append(int(packet['tcp'].window_size))
        except AttributeError:
            pass
    if len(win_sizes) == 0:
        return 0.0
    return sum(win_sizes) / len(win_sizes)

def calculate_pkts_io_ratio(flow, spkts, dpkts):
    if spkts == 0 or dpkts == 0:
        return 0.0
    return spkts / dpkts

def calculate_first_pkt_length(flow):
    if flow['packets']:
        first_packet_len = len(flow['packets'][0])
        return float(first_packet_len)
    else:
        return 0.0

def calculate_max_len_rx(flow):
    max_len_rx = 0.0
    for packet in flow['packets']:
        packet_length = int(packet.length)
        if packet_length > max_len_rx:
            max_len_rx = packet_length
    return float(max_len_rx)

def calculate_min_len_rx(flow):
    min_len_rx = float('inf') 
    for packet in flow['packets']:
        packet_length = int(packet.length)
        if packet_length < min_len_rx:
            min_len_rx = packet_length
    return float(min_len_rx)

def calculate_std_dev_len_rx(flow):
    lengths = [len(packet) for packet in flow['packets']]

    if len(lengths) < 2:
        return 0.0

    return statistics.stdev(lengths)

def calculate_avg_len_rx(flow):
    total_length = 0.0
    packet_count = 0.0

    for packet in flow['packets']:
        packet_length = int(packet.length)
        total_length += packet_length
        packet_count += 1

    if packet_count > 0:
        avg_len_rx = total_length / packet_count
    else:
        avg_len_rx = 0.0

    return float(avg_len_rx)

def calculate_min_iat_rx(flow, timestamps):
    if len(timestamps) <= 1:
        return 0.0
    iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    return float(min(iats))

def calculate_avg_iat_rx(flow, timestamps):
    if len(timestamps) <= 1:
        return 0.0
    iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    return float(statistics.mean(iats))

def calculate_num_ports(flow):
    unique_ports = set()

    for packet in flow['packets']:
        if flow['protocol'] == 'TCP' or flow['protocol'] == 'UDP':
            try:
                destination_port = int(packet.tcp.dstport)
                unique_ports.add(destination_port)
            except AttributeError:
                # Skip packets without a TCP layer
                continue
        else:
            # Return 0.0 for flows not using TCP or UDP
            return 0.0

    num_ports = len(unique_ports)
    return float(num_ports)

def calculate_flow_len(flow):
    total_length = sum(int(packet.length) for packet in flow['packets'])
    return float(total_length)

def calculate_flow_len_rx(flow):
    total_length = sum(int(packet.length) for packet in flow['packets'] if flow['destination_ip'] == str(get_local_ip()))
    return float(total_length)

def calculate_repeated_pkts_ratio(flow):
    packet_lengths = {}
    for packet in flow['packets']:
        length = int(packet.length)
        if length in packet_lengths:
            packet_lengths[length] += 1
        else:
            packet_lengths[length] = 1
    
    max_occurrence = max(packet_lengths.values(), default=0)
    repeated_pkts_ratio = max_occurrence / len(flow['packets'])
    return float(repeated_pkts_ratio)

def calculate_num_connections(flow):
    num_connections = sum(1 for packet in flow['packets'] if 'tcp' in packet and 'SYN' in packet.tcp.flags and 'ACK' in packet.tcp.flags)
    return float(num_connections)

def calculate_num_unique_ipdst(flow):
    unique_ips = set()
    for packet in flow['packets']:
        if 'ip' in packet:
            ip_packet = packet.ip
            if hasattr(ip_packet, 'src'):
                src_ip = ip_packet.src
                unique_ips.add(src_ip)
    num_unique_ipdst = len(unique_ips)
    return float(num_unique_ipdst)

def calculate_start_flow(timestamps):
    if len(timestamps) == 0:
        return 0.0
    start_flow = timestamps[0] % 1
    return "{:.6f}".format(float(start_flow))

def calculate_delta_time_flow(timestamps):
    if len(timestamps) <= 1:
        return 0.0
    delta_time = timestamps[-1] - timestamps[0]
    return "{:.6f}".format(float(delta_time))

def calculate_http_packets(flow):
    http_packets = 0.0
    
    if flow['destination_port'] in {'80', '443'}:
        http_packets = len(flow['packets'])

    return float(http_packets)

def count_spkts(flow):
    spkts = 0.0
    for packet in flow['packets']:
        if 'ip' in packet and packet.ip.src == flow['source_ip']:
            spkts += 1
    return float(spkts)

def count_dpkts(flow):
    dpkts = 0.0
    for packet in flow['packets']:
        if 'TCP' in packet or 'UDP' in packet:
            dpkts += 1
    return float(dpkts)

def get_local_ip():
    try:
        # Create a temporary socket
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))  # Connect to a public IP address
        local_ip = temp_socket.getsockname()[0]  # Retrieve the local IP address
        temp_socket.close()  # Close the temporary socket
        return local_ip
    except socket.error:
        return None