from scapy.all import sniff
from datetime import datetime
from scapy.layers.inet import  TCP

# Empty captured packets list
captured_packets = []

# Capture packets
def capture_packets(interface, num_packets):
    # Start packet capturing and call the packet_callback for each captured packet
    sniff(iface=interface, count=num_packets, prn=packet_callback)
    return captured_packets

# Packet processing callback function
def packet_callback(packet):

    try: 
        # Append packet to the captured packets list 
        captured_packets.append(packet)
        #print(packet.summary())
    
    except Exception as e:
        print(f"Error processing packet: {e}")










