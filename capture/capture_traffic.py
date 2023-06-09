import pyshark
from datetime import datetime

# Empty captured flows list
captured_packets = []

# Capture packets
def capture_packets(interface, num_packets):
    # Create a packet capture object
    capture = pyshark.LiveCapture(interface=interface)

    # Start capturing packets
    capture.sniff(packet_count=num_packets)

    # Process captured packets
    for packet in capture:
        # Append packet summary to the captured packets list
        captured_packets.append(packet)

    return captured_packets


# Empty captured flows lsit
captured_flows = []

# Capture flows
def capture_flows(interface, numb_packets):
    capture = pyshark.LiveCapture(interface=interface)

    # Start capturing packets
    capture.sniff(packet_count=numb_packets)

    '''
    # Process captured packets
    for packet in capture:
        if 'ip' in packet:
            # Extract flow information from the packet
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            source_port = packet[packet.transport_layer].srcport
            destination_port = packet[packet.transport_layer].dstport
            protocol = packet.transport_layer
            
        # Check if the flow already exists in captured_flows
        flow_exists = False
        for flow in captured_flows:
            if (flow['source_ip'] == source_ip and
                    flow['destination_ip'] == destination_ip and
                    flow['source_port'] == source_port and
                    flow['destination_port'] == destination_port and
                    flow['protocol'] == protocol):
                flow_exists = True
                break

        # If the flow doesn't exist, create a new flow
        if not flow_exists:

            new_flow = {
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'source_port': source_port,
                'destination_port': destination_port,
                'protocol': protocol,
                'packets': []  # List to store packets of the flow
            }

            captured_flows.append(new_flow)

        # Append the packet to the corresponding flow
        for flow in captured_flows:
            if (flow['source_ip'] == source_ip and
                    flow['destination_ip'] == destination_ip and
                    flow['source_port'] == source_port and
                    flow['destination_port'] == destination_port and
                    flow['protocol'] == protocol):
                flow['packets'].append(packet)
                break
        '''
    # Process captured packets
    for packet in capture:
        if 'ip' in packet:
            # Extract flow information from the packet
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            source_port = packet[packet.transport_layer].srcport
            destination_port = packet[packet.transport_layer].dstport
            protocol = packet.transport_layer

            # Check if the flow already exists in captured_flows
            flow_exists = False
            for flow in captured_flows:
                if (flow['source_ip'] == source_ip and
                        flow['destination_ip'] == destination_ip and
                        flow['source_port'] == source_port and
                        flow['destination_port'] == destination_port and
                        flow['protocol'] == protocol):
                    flow_exists = True
                    break

            # If the flow doesn't exist, create a new flow
            if not flow_exists:
                new_flow = {
                    'source_ip': source_ip,
                    'destination_ip': destination_ip,
                    'source_port': source_port,
                    'destination_port': destination_port,
                    'protocol': protocol,
                    'packets': []  # List to store packets of the flow
                }
                captured_flows.append(new_flow)

            # Append the packet to the corresponding flow
            for flow in captured_flows:
                if (flow['source_ip'] == source_ip and
                        flow['destination_ip'] == destination_ip and
                        flow['source_port'] == source_port and
                        flow['destination_port'] == destination_port and
                        flow['protocol'] == protocol):
                    flow['packets'].append(packet)
                    break

    return captured_flows