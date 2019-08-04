import scapy, threading
import gc
from threading import *
from random import randint
from scapy.all import *
import os
from datetime import datetime
from tcp_stream import *
from tcp_state import *

streams={}
fwd_flows = set()
rev_flows = set()
def extract_file(output_f='file_extracted'):
    assert output_f is not None
    if not os.path.exists(output_f):
        os.mkdir(output_f)
    outputdir=os.path.join(output_f,datetime.now().strftime('%d_%m_%Y'))
    if not os.path.exists(outputdir):
        os.mkdir(outputdir)
    def process_pkt(pkt):
        if not 'TCP' in pkt or not 'IP' in pkt:
            return
        flow = (create_forward_flow(pkt), create_reverse_flow(pkt))
        if not flow[0] in streams and not flow[1] in streams and is_syn_pkt(pkt):
            streams [flow[0]] = TCPStream(pkt)
            streams [flow[1]] = streams [flow[0]]
            fwd_flows.add(flow[0])
            rev_flows.add(flow[1])
        elif flow[0] in streams:
            is_closed = streams[flow[0]].add_pkt(pkt)#if stream is close then one start extracting file
            if (is_closed or is_finack_pkt(pkt) or is_fin_pkt(pkt)) and flow[0] in fwd_flows:
                print('%s'%(30*'---'))
                print('close a stream and extract file form stream : %s'%flow[0])
                tcp_stream = streams[flow[0]]
                tcp_stream.get_file_data(outputdir)
                del streams[flow[0]]
    return process_pkt

sniff(offline='file2.pcap', prn=extract_file('file_extracted'))
# To use sniffing on interface, use command:
# sniff(iface='eth0', prn=extract_file('file_extracted'))