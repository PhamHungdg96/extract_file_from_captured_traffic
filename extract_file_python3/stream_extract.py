import scapy, threading
import gc
from threading import *
from random import randint
from scapy.all import *

from tcp_stream import *
from tcp_state import *

packet_list =scapy.utils.rdpcap('file1.pcap')
streams={}
fwd_flows = set()
rev_flows = set()
outputdir='file_extracted'
if not outputdir is None:
    if not os.path.exists(outputdir):
        os.mkdir(outputdir)
for pkt in packet_list:
    if not 'TCP' in pkt or not 'IP' in pkt:
        continue
    flow = (create_forward_flow(pkt), create_reverse_flow(pkt))
    if not flow[0] in streams and not flow[1] in streams and is_syn_pkt(pkt):
        streams [flow[0]] = TCPStream(pkt)
        streams [flow[1]] = streams [flow[0]]
        fwd_flows.add(flow[0])
        rev_flows.add(flow[1])
    elif flow[0] in streams:
        streams[flow[0]].add_pkt(pkt)
data_stream=''
for session in fwd_flows:
    tcp_stream = streams[session]
    tcp_stream.get_file_data(outputdir)