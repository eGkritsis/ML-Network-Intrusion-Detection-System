from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from pyod.models.iforest import IForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import os
from datetime import datetime


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
    flow_info['is_sm_ips_ports'] = 1 if (flow_extra_info['source_ip'] == flow_extra_info['destination_ip'] and flow_extra_info['source_port'] == flow_extra_info['destination_port']) else 0
    

    # Encode categorical features
    protocol_encoder = LabelEncoder()
    flow_info['proto'] = protocol_encoder.fit_transform([flow_info['proto']])[0]
    
    service_encoder = LabelEncoder()
    flow_info['service'] = service_encoder.fit_transform([flow_info['service']])[0]
    
    state_encoder = LabelEncoder()
    flow_info['state'] = state_encoder.fit_transform([flow_info['state']])[0]

    #print(f"id: {id}")
    #print(flow_extra_info)
    #print(flow_info)
    #print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")

    return flow_info


def detect_anomaly(captured_flows):
    # Extract flow information
    dataset = []
    n = 0

    for flow in captured_flows:
        n += 1
        flow_info = extract_flow_info(flow, n)
        numeric_values = [float(value) for value in flow_info.values() if isinstance(value, (int, float))]
        dataset.append(numeric_values)

    # Convert the dataset to a numpy array
    dataset = np.array(dataset)

    # Initialize and fit the anomaly detection model
    model = IForest(contamination=0.01)
    model.fit(dataset)

    # Calculate anomaly scores
    anomaly_scores = model.decision_function(dataset)

    # Detect anomalies in the dataset
    anomalies = model.predict(dataset)

    # Generate report
    generate__anomaly_report(captured_flows, anomalies)

    return anomaly_scores


def generate_anomaly_report(captured_flows, anomalies):
    try:
        # Anomalies counter
        counter = 0

        # Print the results
        for i, anomaly in enumerate(anomalies):
            flow_number = i + 1

            print(f"*Flow #{flow_number}*\n")

            if anomaly == 1:
                counter += 1
                print("**Anomaly detected**\n")
            else:
                print("Normal\n")
            print("==============================\n")

        print(f"TOTAL ANOMALIES FOUND: {counter}\n")
        print("==============================\n")

    except Exception as e:
        # Handle any other exceptions that may occur
        print(f"Error processing flow: {str(e)}")

    # Successful message
    print("Report generation completed.\n")


    