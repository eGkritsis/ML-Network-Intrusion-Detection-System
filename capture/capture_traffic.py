import pyshark

# Capture flows
def capture_flows(interface, filter):

    # Empty captured flows lsit
    captured_flows = []

    capture = pyshark.LiveCapture(interface=interface, display_filter=filter)

    try:
        # Start capturing packets
        # Process captured packets
        for packet in capture.sniff_continuously():
            try: 
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
                            'packets': []  
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
            except AttributeError:
                continue
    except KeyboardInterrupt:
        # Stop capturing packets when Ctrl+C is pressed
        capture.close()


    return captured_flows