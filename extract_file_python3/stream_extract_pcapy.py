#!usr/bin/python3
from scapy.all import *
import os
from datetime import datetime
from tcp_stream import *
from tcp_state import *
import socket
from struct import *
import pcapy
import sys
import save_info as save

streams={}
fwd_flows = set()
rev_flows = set()
str_ins='''INSERT INTO ExtractFile(idx,date_time,ip_src,p_src ,ip_dst,p_dst,filename ,size_data ,file_path) VALUES (?,?,?,?,?,?,?,?,?)'''     

def extract_file(output_f='file_extracted'):
    assert output_f is not None
    if not os.path.exists(output_f):
        os.mkdir(output_f)
    outputdir=os.path.join(output_f,datetime.now().strftime('%d_%m_%Y'))
    if not os.path.exists(outputdir):
        os.mkdir(outputdir)
    return outputdir

def process_pkt(pkt,outputdir, conn=None):
    global str_ins
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
            IDX=datetime.now().strftime('%s')
            nowable=datetime.now()
            print(len(streams[flow[0]].pkts))
            print('%s'%(30*'---'))
            print('close a stream and extract file form stream : %s'%streams[flow[0]].get_client_server_str())
            tcp_stream = streams[flow[0]]
            list_result=tcp_stream.get_file_data(outputdir)
            del streams[flow[0]]
            del streams[flow[1]]
            if conn is not None and list_result is not None and len(list_result) > 0:
                for result in list_result:
                    (src, dst,size_data,filename,file_path)=result
                    ip_src, p_src = src.split(':')
                    ip_dst, p_dst = dst.split(':')
                    data=(int(IDX),str(nowable),ip_src, int(p_src),ip_dst, int(p_dst),filename,size_data,file_path)
                    with conn:
                        result_save=save.insert_data(conn,str_ins,data)
                        if result_save is not None:
                            print('the ID of entry is %s what is saved in database'% result_save)

def main(outputdir, conn=None):
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
    cap = pcapy.open_live(dev , 65536 , True , 10)

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
            
            process_pkt(ip_pkt,outputdir,conn)


        elif proto == '86':
            print('capture packet ARP')
        elif proto == '86DD':
            print('capture packet IPv6')
        else:
            print('capture packet %s'%proto)

if __name__=='__main__':
    # IDX,nowable,ip_src, p_src,ip_dst, p_dst,filename,size_data,file_path
    sql_create_ExtractFile_table = """ CREATE TABLE IF NOT EXISTS ExtractFile(
                                        idx integer PRIMARY KEY,
                                        date_time text NOT NULL,
                                        ip_src text NOT NULL,
                                        p_src integer NOT NULL,
                                        ip_dst text NOT NULL,
                                        p_dst integer NOT NULL,
                                        filename text,
                                        size_data text,
                                        file_path text
                                    ); """
    outputdir=extract_file()
    main(outputdir)
    # conn=save.create_connection('DBExtractFile.db')
    # with conn:
    #     save.create_table(conn,sql_create_ExtractFile_table)
    #     main(outputdir,conn)