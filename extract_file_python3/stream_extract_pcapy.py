from scapy.all import *
import os
from datetime import datetime
from tcp_stream import *
from tcp_state import *
import socket
from struct import *
import pcapy
import sys

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
    return outputdir

def process_pkt(pkt,outputdir):
    if not 'TCP' in pkt or not 'IP' in pkt:
        return
    flow = (create_forward_flow(pkt), create_reverse_flow(pkt))
    if (not flow[0] in streams) and (not flow[1] in streams) and is_syn_pkt(pkt):
        streams [flow[0]] = TCPStream(pkt)
        streams [flow[1]] = streams [flow[0]]
        fwd_flows.add(flow[0])
        rev_flows.add(flow[1])
    elif flow[0] in streams:
        is_closed = streams[flow[0]].add_pkt(pkt)#if stream is close then one start extracting file
        if is_closed:
            print(len(streams[flow[0]].pkts))
            print('%s'%(30*'---'))
            print('close a stream and extract file form stream : %s'%streams[flow[0]].get_client_server_str())
            tcp_stream = streams[flow[0]]
            tcp_stream.get_file_data(outputdir)
            del streams[flow[0]]
            del streams[flow[1]]

def main(outputdir):
    devices = pcapy.findalldevs()
    print (devices)
    
    #ask user to enter device name to sniff
    print('Available devices are :')
    for d in devices :
        print (d)
    
    dev = input('Enter device name to sniff : ')
    
    print ('Sniffing device' + dev)
    
    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live(dev , 65536 , 1 , 0)

    #start sniffing packets
    while(1) :
        (header, packet) = cap.next()
        print('%s: captured %d bytes, truncated to %d bytes' %(datetime.now(), header.getlen(), header.getcaplen()))
        # parse_packet(packet)
        if len(packet) <=0:
            break
        eth_len = 14
        eth_header = packet[:eth_len]
        eth_data = packet[eth_len:]
        dest_mac,src_mac,proto_field1,proto_field2 = struct.unpack('!6s6scc' , eth_header)
        proto = ''.join(map(str,proto_field1)) + ''.join(map(str,proto_field2))
        if proto == '80':
            print('capture packet IPv4')
            ip_pkt = IP(packet[eth_len:])
            
            process_pkt(ip_pkt,outputdir)


        elif proto == '86':
            print('capture packet ARP')
        elif proto == '86DD':
            print('capture packet IPv6')
        else:
            print('capture packet %s'%proto)

if __name__=='__main__':
    outputdir=extract_file()
    main(outputdir)