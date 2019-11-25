import scapy, threading
import gc
from threading import *
from random import randint
from scapy.all import *
import os
from datetime import datetime
from tcp_stream import *
from tcp_state import *
import socket, struct, os, array

class Sniff():
    def  __init__(self, interface="lo", offline=None):
        # assert (interface is not None) or (offline is not None)
        if interface is not None:
            offline=None
        self.interface=interface
        self.offline=offline

        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        if interface is not None:
            self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
            self.ins.bind((self.interface, ETH_P_ALL))

        self.streams={}
        self.fwd_flows = set()
        self.rev_flows = set()
        self.outputdir=None
        self.extract_file()
        

    def extract_file(self,output_f='file_extracted'):
        assert output_f is not None
        if not os.path.exists(output_f):
            os.mkdir(output_f)
        self.outputdir=os.path.join(output_f,datetime.now().strftime('%d_%m_%Y'))
        if not os.path.exists(self.outputdir):
            os.mkdir(self.outputdir)
        
    def process_pkt(self,pkt):
        if not 'TCP' in pkt or not 'IP' in pkt:
            return
        flow = (create_forward_flow(pkt), create_reverse_flow(pkt))
        if (not flow[0] in self.streams) and (not flow[1] in self.streams) and is_syn_pkt(pkt):
            self.streams [flow[0]] = TCPStream(pkt)
            self.streams [flow[1]] = self.streams [flow[0]]
            self.fwd_flows.add(flow[0])
            self.rev_flows.add(flow[1])
        elif flow[0] in self.streams:
            is_closed = self.streams[flow[0]].add_pkt(pkt)#if stream is close then one start extracting file
            if is_closed:
                print(len(self.streams[flow[0]].pkts))
                print('%s'%(30*'---'))
                print('close a stream and extract file form stream : %s'%self.streams[flow[0]].get_client_server_str())
                tcp_stream = self.streams[flow[0]]
                tcp_stream.get_file_data(self.outputdir)
                del self.streams[flow[0]]
                del self.streams[flow[1]]
    def recv(self):
        if self.interface:
            while True:
                pkt, sa_ll = self.ins.recvfrom(65535)
                if len(pkt) <= 0:
                    break
                eth_header = struct.unpack("!6s6sH", pkt[0:14])
                if eth_header[2] != 0x800 :
                    continue
                ip_header = pkt[14:34]
            
                ip_pkt = IP(pkt[14:])

                self.process_pkt(ip_pkt)
        if self.offline:
            pkts=rdpcap(self.offline)
            for pkt in pkts:
                self.process_pkt(pkt)
# _sniff = Sniff(interface=None,offline='jpg_png.pcap')
_sniff = Sniff(interface=None,offline='get.pcap')
_sniff.recv()