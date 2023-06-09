import pandas as pd
import joblib
from datetime import datetime
from sklearn.preprocessing import OneHotEncoder, LabelBinarizer
import numpy as np
from sklearn.impute import SimpleImputer

    
# Extract and preprocess the necessary information from each flow of packets
def extract_flow_info(flow, id):
    flow_extra_info = {}
    flow_extra_info['source_ip'] = flow['source_ip']
    flow_extra_info['destination_ip'] = flow['destination_ip']
    flow_extra_info['source_port'] = flow['source_port']
    flow_extra_info['destination_port'] = flow['destination_port']

    flow_info = {}

    # Calculate timestamps
    timestamps = [datetime.timestamp(packet.sniff_time) for packet in flow['packets']]
    
    flow_info['id'] = id
    flow_info['dur'] = calculate_flow_duration(flow)
    flow_info['proto'] = flow['protocol']
    flow_info['service'] = find_service(flow)
    flow_info['state'] = find_state(flow)
    flow_info['spkts'] = count_spkts(flow)
    flow_info['dpkts'] = count_dpkts(flow)
    flow_info['sbytes'] = calculate_sbytes(flow)
    flow_info['dbytes'] = calculate_dbytes(flow)
    flow_info['rate'] = flow_info['sbytes'] / flow_info['dur'] if flow_info['dur'] != 0 else 0
    flow_info['sttl'] = calculate_sstl(flow)
    flow_info['dttl'] = calculate_dttl(flow)
    flow_info['sload'] = (flow_info['sbytes'] * 8) / flow_info['dur'] if flow_info['dur'] != 0 else 0
    flow_info['dload'] = calculate_dload(flow_info)
    flow_info['sloss'] = flow_info['spkts'] - flow_info['dpkts']
    flow_info['dloss'] = flow_info['dpkts'] - flow_info['spkts']
    flow_info['sinpkt'] = flow_info['dur'] / flow_info['spkts'] if flow_info['spkts'] != 0 else 0
    flow_info['dinpkt'] = flow_info['dur'] / flow_info['dpkts'] if flow_info['dpkts'] != 0 else 0
    flow_info['sjit'] = calculate_jitter(timestamps, flow_info['spkts'])
    flow_info['djit'] = calculate_jitter(timestamps, flow_info['dpkts'])
    flow_info['swin'] = flow['packets'][0].tcp.window_size if flow_info['proto'] == 'TCP' and len(flow['packets']) > 0 else 0
    flow_info['stcpb'] = flow['packets'][0].tcp.seq if flow_info['proto'] == 'TCP' and len(flow['packets']) > 0 else 0
    flow_info['dtcpb'] = flow['packets'][-1].tcp.ack if flow_info['proto'] == 'TCP' and len(flow['packets']) > 0 else 0
    flow_info['dwin'] = flow['packets'][-1].tcp.window_size if flow_info['proto'] == 'TCP' and len(flow['packets']) > 0 else 0
    flow_info['tcprtt'] = calculate_tcprtt(flow, timestamps)
    flow_info['synack'] = calculate_synack(flow, timestamps)
    flow_info['ackdat'] = calculate_ackdat(flow, timestamps)
    flow_info['smean'] = calculate_smean(flow)
    flow_info['dmean'] = calculate_dmean(flow)
    flow_info['trans_depth'] = calculate_trans_depth(flow)
    flow_info['response_body_len'] = calculate_response_body_len(flow)
    flow_info['ct_srv_src'] = sum(1 for packet in flow['packets'] if 'tcp' in packet and packet.ip.src == flow['source_ip'])
    flow_info['ct_state_ttl'] = sum(1 for packet in flow['packets'] if 'ip' in packet and int(packet.ip.ttl) <= 32 and 'tcp' in packet)
    flow_info['ct_dst_ltm'] = calculate_ct_dst_ltm(flow, flow_extra_info['destination_ip'])
    flow_info['ct_src_dport_ltm'] = calculate_cs_src_dport_ltm(flow, flow_extra_info['source_ip'], flow_extra_info['destination_port'])
    flow_info['ct_dst_sport_ltm'] = calculate_ct_dst_sport_ltm(flow, flow_extra_info['destination_ip'], flow_extra_info['source_port'])
    flow_info['ct_dst_src_ltm'] = calculate_ct_dst_src_ltm(flow, flow_extra_info['destination_ip'], flow_extra_info['source_ip'])
    flow_info['is_ftp_login'] = len([packet for packet in flow['packets'] if 'ftp' in packet]) > 0
    flow_info['ct_ftp_cmd'] = len([packet for packet in flow['packets'] if 'ftp' in packet])
    flow_info['ct_flw_http_mthd'] = len([packet for packet in flow['packets'] if 'http' in packet])
    flow_info['ct_src_ltm'] = calculate_ct_src_ltm(flow, flow_extra_info['source_ip'])
    flow_info['ct_srv_dst'] = len(set(packet.tcp.dstport for packet in flow['packets'] if 'tcp' in packet))
    flow_info['is_sm_ips_ports'] = (flow_extra_info['source_ip'] == flow_extra_info['destination_ip'] and flow_extra_info['source_port'] == flow_extra_info['destination_port'])

    # Set the attack category and label as 'N/A' initially
    flow_info['attack_cat'] = 0.0

    # Convert selected features to appropriate data types
    flow_info['dur'] = float(flow_info['dur'])
    flow_info['spkts'] = int(flow_info['spkts'])
    flow_info['dpkts'] = int(flow_info['dpkts'])
    flow_info['sbytes'] = int(flow_info['sbytes'])
    #flow_info['dbytes'] = int(flow_info['dbytes'])
    flow_info['dbytes'] = 0
    flow_info['rate'] = float(flow_info['rate'])
    flow_info['sttl'] = int(flow_info['sttl'])
    flow_info['dttl'] = int(flow_info['dttl'])
    flow_info['sload'] = float(flow_info['sload'])
    flow_info['dload'] = float(flow_info['dload'])
    flow_info['sloss'] = int(flow_info['sloss'])
    flow_info['dloss'] = int(flow_info['dloss'])
    flow_info['sinpkt'] = float(flow_info['sinpkt'])
    flow_info['dinpkt'] = float(flow_info['dinpkt'])
    flow_info['sjit'] = float(flow_info['sjit'])
    flow_info['djit'] = float(flow_info['djit'])
    flow_info['swin'] = int(flow_info['swin'])
    flow_info['stcpb'] = int(flow_info['stcpb'])
    flow_info['dtcpb'] = int(flow_info['dtcpb'])
    flow_info['dwin'] = int(flow_info['dwin'])
    flow_info['tcprtt'] = float(flow_info['tcprtt'])
    flow_info['synack'] = float(flow_info['synack'])
    flow_info['ackdat'] = float(flow_info['ackdat'])
    flow_info['smean'] = float(flow_info['smean'])
    flow_info['dmean'] = float(flow_info['dmean'])
    flow_info['trans_depth'] = int(flow_info['trans_depth'])
    flow_info['response_body_len'] = int(flow_info['response_body_len'])
    flow_info['ct_srv_src'] = int(flow_info['ct_srv_src'])
    flow_info['ct_srv_dst'] = int(flow_info['ct_srv_dst'])
    flow_info['ct_dst_ltm'] = int(flow_info['ct_dst_ltm'])
    flow_info['ct_src_ltm'] = int(flow_info['ct_src_ltm'])
    flow_info['ct_src_dport_ltm'] = int(flow_info['ct_src_dport_ltm'])
    flow_info['ct_dst_sport_ltm'] = int(flow_info['ct_dst_sport_ltm'])
    flow_info['ct_dst_src_ltm'] = int(flow_info['ct_dst_src_ltm'])
    flow_info['is_ftp_login'] = int(flow_info['is_ftp_login'])
    flow_info['ct_ftp_cmd'] = int(flow_info['ct_ftp_cmd'])
    flow_info['ct_flw_http_mthd'] = int(flow_info['ct_flw_http_mthd'])
    flow_info['ct_src_ltm'] = int(flow_info['ct_src_ltm'])
    flow_info['ct_srv_dst'] = int(flow_info['ct_srv_dst'])

    
    # One-hot encoding for categorical features
    protocol_encoder = LabelBinarizer()
    protocol_encoded = protocol_encoder.fit_transform([flow_info['proto']])
    flow_info['proto'] = np.array(protocol_encoded[0])

    service_encoder = LabelBinarizer()
    service_encoded = service_encoder.fit_transform([flow_info['service']])
    flow_info['service'] = np.array(service_encoded[0])

    state_encoder = LabelBinarizer()
    state_encoded = state_encoder.fit_transform([flow_info['state']])
    flow_info['state'] = np.array(state_encoded[0])
    

    return flow_info

def flow_detection(captured_flows, model):
    # Detect anomalies using the Random Forest model provided

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
        # Handle the case when there are no valid samples
        # For example, return None or an empty list
        return None

    # Use the model to predict labels for the preprocessed flows
    predicted_labels = detect_anomaly(flow_info_df, model)

    return predicted_labels

def detect_anomaly(info, model):
    predicted_labels = model.predict(info)

    return predicted_labels

# Load the trained Random Forest model
def load_model(model_file):
    # Implement the function to load the trained Random Forest model from the saved file
    # Return the loaded model
    model = joblib.load('model.pkl')
    return model

    
def generate_report(predicted_labels):
    # Implement the function to generate a report based on the predicted labels
    # Summarize the detection results, such as the number of normal flows, malicious flows, etc.
    # Print or save the report as per your requirements
    normal_count = np.count_nonzero(predicted_labels == 0)
    malicious_count = np.count_nonzero(predicted_labels == 1)
    print(f"Number of normal flows: {normal_count}")
    print(f"Number of malicious flows: {malicious_count}")
    print("Generate report complete.")


# --------------------------------- FLOW'S INFORMATON CALCULATION FUNCTIONS -----------------------------------------------------

def calculate_flow_duration(flow):
    first_packet_time = datetime.strptime(flow['packets'][0].frame_info.time, "%b %d, %Y %H:%M:%S.%f000 GTB Daylight Time")
    last_packet_time = datetime.strptime(flow['packets'][-1].frame_info.time, "%b %d, %Y %H:%M:%S.%f000 GTB Daylight Time")
    duration = last_packet_time - first_packet_time
    return duration.total_seconds()

def find_service(flow):
    well_known_ports = {
        20: 'ftp',
        21: 'ftp',
        25: 'smtp',
        80: 'http',
        443: 'https',
        134: 'IMAP',
        53: 'DNS',
    }

    dport = int(flow['destination_port'])
    if dport in well_known_ports:
        return well_known_ports[dport]
    else:
        return 'Unknown'

def find_state(flow):
    # Infer state based on TCP flags
    tcp_flags = set()
    for packet in flow['packets']:
        if 'TCP' in packet:
            tcp_flags.update(packet['TCP'].flags.split(','))

    if 'FIN' in tcp_flags:
        return 'FIN'
    elif 'SYN' in tcp_flags:
        return 'CON'
    elif 'RST' in tcp_flags:
        return 'INT'
    elif 'ACK' in tcp_flags:
        return 'REQ'
    else:
        return 'Unknown'
    
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

def calculate_sbytes(flow):
    sbytes = 0
    for packet in flow['packets']:
        if 'ip' in packet:
            if packet.ip.src == flow['source_ip']:
                sbytes += int(packet.ip.len)
    return sbytes

def calculate_dbytes(flow):
    dbytes = 0
    for packet in flow['packets']:
        if 'ip' in packet:
            if packet.ip.dst == flow['source_ip']:
                dbytes += int(packet.ip.len)


def calculate_sstl(flow):
    sttl_values = [packet.ip.ttl for packet in flow['packets'] if 'ip' in packet]
    if sttl_values:
        sttl = max(sttl_values)
    else:
        sttl = 0

    return sttl

def calculate_dttl(flow):
    dttl_values = [packet.ip.ttl for packet in flow['packets'] if 'ip' in packet]
    if dttl_values:
        dttl = max(dttl_values)
    else:
        dttl = 0

    return dttl

def calculate_dload(flow_info):
    dbytes = flow_info['dbytes']
    dur = flow_info['dur']
    if dbytes is not None and dur != 0:
        dload = (dbytes * 8) / dur
    else:
        dload = 0

    return dload

def calculate_jitter(timestamps, spkts):
    jitter = 0
    if isinstance(spkts, int):
        spkts = [spkts] * len(timestamps)
    for i in range(1, len(timestamps)):
        jitter += abs(timestamps[i] - timestamps[i-1]) - (spkts[i] + spkts[i-1])
    return jitter

def calculate_tcprtt(flow, timestamps):
    if len(timestamps) < 3:
        return 0
    syn_timestamps = timestamps[::2]
    ack_timestamps = timestamps[1::2]
    rtt = [ack - syn for syn, ack in zip(syn_timestamps, ack_timestamps)]
    return sum(rtt) / len(rtt)

def calculate_synack(flow, timestamps):
    if len(timestamps) < 2:
        return 0
    syn_timestamps = timestamps[::2]
    ack_timestamps = timestamps[1::2]
    return sum(ack - syn for syn, ack in zip(syn_timestamps, ack_timestamps)) / len(timestamps)

def calculate_ackdat(flow, timestamps):
    if len(timestamps) < 2:
        return 0
    ack_timestamps = timestamps[::2]
    dat_timestamps = timestamps[1::2]
    return sum(dat - ack for ack, dat in zip(ack_timestamps, dat_timestamps)) / len(timestamps)

def calculate_smean(flow):
    slen = 0
    for packet in flow['packets']:
        if 'tcp' in packet and 'len' in packet.tcp.field_names:
            slen += int(packet.tcp.len)
        elif 'udp' in packet and 'length' in packet.udp.field_names:
            slen += int(packet.udp.length)
    if slen > 0:
        return slen / len(flow['packets'])
    else:
        return 0

def calculate_dmean(flow):
    dlen = 0
    for packet in flow['packets']:
        if 'tcp' in packet and 'len' in packet.tcp.field_names:
            dlen += int(packet.tcp.len)
        elif 'udp' in packet and 'length' in packet.udp.field_names:
            dlen += int(packet.udp.length)
    if dlen > 0:
        return dlen / len(flow['packets'])
    else:
        return 0

def calculate_trans_depth(flow):
    trans_depth = 0
    for packet in flow['packets']:
        if 'tcp' in packet and 'analysis_tcp_analysis_flags_tree' in packet.tcp.field_names:
            trans_depth = max(trans_depth, int(packet.tcp.analysis_tcp_analysis_flags_tree.get_field_value("tcp.flags.ack_tree")))
        elif 'rtcp' in packet and 'analysis_flags_tree' in packet.rtcp.field_names:
            trans_depth = max(trans_depth, int(packet.rtcp.analysis_flags_tree.get_field_value("tcp.flags.ack_tree")))
    return trans_depth

def calculate_response_body_len(flow):
    response_body_len = 0
    for packet in flow['packets']:
        if 'http' in packet and 'response_code' in packet.http.field_names and packet.http.response_code == '200':
            response_body_len += int(packet.length)
    return response_body_len

def calculate_ct_dst_ltm(flow, destination_ip):
    unique_dest_ips = set()
    for packet in flow['packets']:
        if packet.ip.dst == destination_ip:
            unique_dest_ips.add(packet.ip.src)
    return len(unique_dest_ips)

def calculate_cs_src_dport_ltm(flow, source_ip, destination_port):
    unique_src_ips = set()
    for packet in flow['packets']:
        if packet.ip.src == source_ip and packet[packet.transport_layer].dstport == destination_port:
            unique_src_ips.add(packet.ip.dst)
    return len(unique_src_ips)

def calculate_ct_dst_sport_ltm(flow, destination_ip, source_port):
    unique_dest_ips = set()
    for packet in flow['packets']:
        if packet.ip.dst == destination_ip and packet[packet.transport_layer].srcport == source_port:
            unique_dest_ips.add(packet.ip.src)
    return len(unique_dest_ips)

def calculate_ct_dst_src_ltm(flow, destination_ip, source_ip):
    unique_dest_src_ips = set()
    for packet in flow['packets']:
        if packet.ip.dst == destination_ip and packet.ip.src == source_ip:
            unique_dest_src_ips.add((packet.ip.dst, packet.ip.src))
    return len(unique_dest_src_ips)

def calculate_ct_src_ltm(flow, source_ip):
    src_ip_counts = {}
    for packet in flow['packets']:
        src_ip = packet.ip.src
        if src_ip == source_ip:
            if src_ip in src_ip_counts:
                src_ip_counts[src_ip] += 1
            else:
                src_ip_counts[src_ip] = 1
    return len(src_ip_counts)