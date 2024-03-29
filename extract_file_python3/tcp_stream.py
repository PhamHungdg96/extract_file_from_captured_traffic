from scapy.all import *
from random import randint
import scapy
from random import randint
from tcp_state import TCPStateMachine
import zlib
from datetime import datetime
import gzip
from io import StringIO
import os
from data_recognizers.data_recognizer import DataRecognizer

from threading import *

HEADER = "Time Flow_with_Direction PktPayload ClientDataTransfered ServerDataTransfered TotalData TimeBetweenLastPkt TimeBetweenLastClientPacket TimeBetweenLastServerPacket  TotalTimeElapsed"


MAX = 2 ** 32 - 1

FLOW_NAME = "T:%s_C:%s:%s_S:%s:%s"

class TCPStream:
    def __init__(self, pkt ):
        self.src = pkt["IP"].src 
        self.dst = pkt["IP"].dst
        self.sport = pkt["TCP"].sport
        self.dport = pkt["TCP"].dport        
        self.time = pkt.time        
        self.tcp_state = TCPStateMachine(pkt)
        self.flows = self.tcp_state.flows
        self.pkts = {self.time:pkt}
        self.ordered_pkts  = None
        self.last_time_written = 0.0
        self.pcap_file = None
        self.couchdb_file = None
        self.flow_file = None

    def len_pkts(self):
        return len(list(self.pkts.keys()))
    
    def destroy(self, pkts_cnt=0):
        #self.ordered_pkts = None       
        keys = list(self.pkts.keys())
        print(("destroying packets for %s"%self.get_stream_name()))
        if pkts_cnt > 0:
           keys = keys[:pkts_cnt]
           print(("\t...Destroying the first %d pkts"%pkts_cnt))
        
        if not self.ordered_pkts is None and len(self.ordered_pkts) >= pkts_cnt:
            for i in self.ordered_pkts[:pkts_cnt]:
                del i
        
        self.ordered_pkts = None
        
        for key in keys:
            del self.pkts[key]

    def get_stream_name(self):
        global FLOW_NAME
        return FLOW_NAME%(self.time, self.src, self.sport, self.dst, self.dport)
        
    def get_stream_keys(self):
        global HEADER
        return HEADER.split()
    
    def add_pkt(self, pkt):
        is_closed = self.tcp_state.next_state(pkt)
        self.pkts[pkt.time] = pkt
        self.last_time = pkt.time
        return is_closed
        
    def create_client_directed_flow(self):
        return "%s:%s ==> %s:%s"%(self.src,str(self.sport),self.dst,str(self.dport))
    
    def create_server_directed_flow(self):
        return "%s:%s ==> %s:%s"%(self.dst,str(self.dport),self.src,str(self.sport),)

    def get_client_server_str(self):
        return "%s:%s ==> %s:%s"%(self.src,str(self.sport),self.dst,str(self.dport))

    def get_server_client_str(self):
        return "%s:%s <== %s:%s"%(self.dst,str(self.dport),self.src,str(self.sport))

    def get_client_server(self):
        return 0

    def get_server_client(self):
        return 1
    
    def interp_direction(self, dir):
        if dir == 0:
           return self.get_client_server_str()
        elif dir == 1:
           return self.get_server_client_str()
        raise Exception("Not a valid direction for the client server")

    def get_order_pkts(self, pkts_cnt=0):
        # caching mechanism
        if self.ordered_pkts is None or len(self.ordered_pkts) != len(list(self.pkts.keys())):
            times = list(self.pkts.keys())
            times.sort()
            self.ordered_pkts = [self.pkts[time] for time in times]
        if pkts_cnt > 0:
           return self.ordered_pkts[:pkts_cnt]
        return self.ordered_pkts

    def get_app_stream_summary(self, pkts_cnt=0):
        global HEADER
        pkts = self.get_order_pkts(pkts_cnt)
        pkt_summary = []#[HEADER]
        flow_total = 0
        client_total = 0.0
        server_total = 0.0
        
        last_client_pkt =  None
        last_server_pkt = None
        last_client_pkt_time = 0.0
        last_server_pkt_time = 0.0
        
        i = 0
        while i < len(pkts):
            pkt = pkts[i]
            flow_info = ''
            payload_len = len(pkt['TCP'].payload)
            flow_total += payload_len
            time_elapsed, time_last_pkt = self.packet_time_spacing_idx(pkts, i)
            
            if self.src == pkt['IP'].src:
                #flow_info = self.get_server_client_str()
                flow_info = self.get_client_server()
                if not last_client_pkt is None:
                    last_client_pkt_time = self.packet_time_spacing_pkt(pkt, last_client_pkt)
                last_client_pkt = pkt
                client_total += len(pkt['TCP'].payload)
            else:
                #flow_info = self.get_client_server_str()
                flow_info = self.get_server_client()
                if not last_server_pkt is None:
                    last_server_pkt_time = self.packet_time_spacing_pkt(pkt,last_server_pkt)
                last_server_pkt = pkt
                server_total += len(pkt['TCP'].payload)

            pkt_summary.append([ str(pkt.time), 
                                        flow_info, 
                                        str(payload_len), 
                                        str(client_total),
                                        str(server_total),
                                        str(flow_total),
                                        str(time_last_pkt),
                                        str(last_client_pkt_time),
                                        str(last_server_pkt_time),
                                        str(time_elapsed)])
            i+=1
        return pkt_summary
            
    def get_stream_summary(self, pkts_cnt=0):
        pkts = self.get_order_pkts(pkts_cnt)
        pkt_summary = []# [HEADER]
        flow_total = 0
        client_total = 0.0
        server_total = 0.0
        
        last_client_pkt =  None
        last_server_pkt = None
        last_client_pkt_time = 0.0
        last_server_pkt_time = 0.0
        
        i = 0
        while i < len(pkts):
            pkt = pkts[i]
            flow_info = ''
            payload_len = len(pkt['TCP'])
            flow_total += payload_len
            time_elapsed, time_last_pkt = self.packet_time_spacing_idx(pkts, i)
            
            if self.src == pkt['IP'].src:
                flow_info = self.get_server_client_str()
                if not last_client_pkt is None:
                    last_client_pkt_time = self.packet_time_spacing_pkt(pkt, last_client_pkt)
                last_client_pkt = pkt
                client_total += len(pkt['TCP'])
            else:
                flow_info = self.get_client_server_str()
                if not last_server_pkt is None:
                    last_server_pkt_time = self.packet_time_spacing_pkt(pkt,last_server_pkt)
                last_server_pkt = pkt
                server_total += len(pkt['TCP'])


            pkt_summary.append([ str(pkt.time), 
                                        flow_info, 
                                        str(payload_len), 
                                        str(client_total),
                                        str(server_total),
                                        str(flow_total),
                                        str(time_last_pkt),
                                        str(last_client_pkt_time),
                                        str(last_server_pkt_time),
                                        str(time_elapsed)])
            i+=1
        return pkt_summary

            
    def get_ip_summary(self, pkts_cnt=0):
        pkts = self.get_order_pkts(pkts_cnt)
        pkt_summary = []# [HEADER]
        flow_total = 0
        client_total = 0
        server_total = 0
        
        last_client_pkt =  None
        last_server_pkt = None
        last_client_pkt_time = 0.0
        last_server_pkt_time = 0.0
        
        i = 0
        while i < len(pkts):
            pkt = pkts[i]
            flow_info = ''
            payload_len = len(pkt['IP'])
            flow_total += payload_len
            time_elapsed, time_last_pkt = self.packet_time_spacing_idx(pkts, i)
            
            if self.src == pkt['IP'].src:
                flow_info = self.get_server_client_str()
                if not last_client_pkt is None:
                    last_client_pkt_time = self.packet_time_spacing_pkt(pkt, last_client_pkt)
                last_client_pkt = pkt
                client_total += len(pkt['IP'])
            else:
                flow_info = self.get_client_server_str()
                if not last_server_pkt is None:
                    last_server_pkt_time = self.packet_time_spacing_pkt(pkt,last_server_pkt)
                last_server_pkt = pkt
                server_total += len(pkt['IP'])


            pkt_summary.append([ str(pkt.time), 
                                        flow_info, 
                                        str(payload_len), 
                                        str(client_total),
                                        str(server_total),
                                        str(flow_total),
                                        str(time_last_pkt),
                                        str(last_client_pkt_time),
                                        str(last_server_pkt_time),
                                        str(time_elapsed)])
            i+=1
        return pkt_summary


    def packet_time_spacing_idx(self, pkts, idx):
        if idx < 1:      return 0.0, 0.0
        return self.packet_time_spacing_pkt(pkts[idx], pkts[0]), self.packet_time_spacing_pkt(pkts[idx], pkts[idx-1])
    
    def packet_time_spacing_pkt(self, pkt_a, pkt_b):
        return pkt_a.time - pkt_b.time
    

    def write_flow(self, filename, pkts_cnt=0):
        if self.flow_file is None:
           self.flow_file =open(filename+".app_flow", 'w') 
        
        flow_infos = []
        flows = self.get_app_stream_summary(pkts_cnt)
        for flow_info in flows:
            flow_infos.append(" ".join([str(i) for i in flow_info]))
            
        self.flow_file.write("\n".join(flow_infos)+"\n")
        self.flow_file.flush()
    
    def write_pcap(self, filename, pkts_cnt=0):
        if self.pcap_file is None:
           self.pcap_file = scapy.utils.PcapWriter(filename+".pcap")
        
        pkts = self.get_order_pkts(pkts_cnt)
        self.pcap_file.write(pkts)
        self.pcap_file.flush()
        
        
    def organize_streams(self):
        data = {}
        seq_nos = {}
        order_pkts=self.get_order_pkts()
        # print(order_pkts)
        for pkt in order_pkts:
            tcpp = pkt['TCP']
            seq = tcpp.seq
            sport = tcpp.sport
            dport = tcpp.dport
            s_ip=pkt['IP'].src
            d_ip=pkt['IP'].dst

            keys='%s:%s=>%s:%s'%(s_ip,sport,d_ip,dport)
            if not keys in data:
                data[keys] = []
                seq_nos[keys] = []
            
            if seq in seq_nos[keys]:
                # retransmit
                continue

            if Raw in tcpp:
                data[keys].append([tcpp.seq, tcpp[Raw].load])
                seq_nos[keys].append(seq)
        return seq_nos, data

    def get_stream_data(self):
        seq_nos, data = self.organize_streams()
        streams = {k:bytes() for k in data.keys()}
        # print(seq_nos)
        for sport, seqs_payloads in data.items():
            stream = b''
            for seq, payload in seqs_payloads:
                stream = stream + payload
            streams[sport] = stream
        return streams
    
    
    def get_file_data(self,output_path):
        _, data = self.organize_streams()
        # streams = {k:bytes() for k in data.keys()}
        for _key, seqs_payloads in data.items():
            stream_data = b''
            _header_exist=False
            for _, payload in seqs_payloads:
                stream_data = stream_data + payload
            # print(stream_data)
            try:
                _header = stream_data[stream_data.index(b"HTTP/1."):stream_data.index(b"\r\n\r\n")+2]
                    
                if _header:
                    # with open('payload', "wb") as fo:
                    #     fo.write(stream_data)
                    #     fo.close()
                    _header_exist=True
            except:
                _header_exist=False
                print('not exist file in flow %s'%_key)
            if _header_exist:
                _header = stream_data[:stream_data.index(b"\r\n\r\n")+2]
                http_header_parsed_raw = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", _header.decode("utf8")))
                http_header_parsed = {k.lower(): http_header_parsed_raw[k] for k in http_header_parsed_raw}
                print(http_header_parsed)
                if "content-type" in http_header_parsed.keys():
                    _content_form=stream_data[stream_data.index(b"\r\n\r\n")+4:]
                    if "content-encoding" in http_header_parsed.keys():
                        _content_form = self.decompress_form(_content_form,\
                                        http_header_parsed["content-encoding"])
                    
                    if "multipart/form-data" in http_header_parsed["content-type"]:
                        boundary=''
                        if "boundary" in http_header_parsed["content-type"]:
                            boundary = http_header_parsed["content-type"].split('boundary=')[1]
                            # boundary=('\r\n--%s--\r\n'%boundary).encode()
                        return self.extract_payload_form(boundary,_content_form,output_path, _key)
                    else: 
                        print(len(_content_form))
                        endFile,occ=DataRecognizer().find_out(_content_form)
                        filename='.%s'%endFile
                        if occ is not None:
                            payload_form=_content_form[occ[0]:]
                            file_path = output_path + "/" + '%s_%s'%(datetime.now().strftime('%s'),filename)
                            fd = open(file_path, "wb")
                            fd.write(payload_form)
                            fd.close()
                            print('the file is written in %s'%file_path)
                            return [(_key.split('=>')[0],_key.split('=>')[1],len(payload_form),filename,file_path)]

                else: print('Not exist file in flow %s'%_key)
        return None
                            
    def decompress_form(self,payload,type_compress):
        if type_compress == "gzip":
            return gzip.GzipFile(fileobj=StringIO(payload)).read()
        elif type_compress == "deflate":
            return zlib.decompress(payload)
        else:
            return payload

    def extract_payload_form(self,boundary, _content_form, output_path,_key):
        filename=''
        boundary_first = ('--%s\r\n'%boundary).encode()
        boundary_split= ('\r\n--%s\r\n'%boundary).encode()
        boundary_last = ('\r\n--%s--\r\n'%boundary).encode()

        #split multi-formdata
        list_content_form=list()
        try:
            list_content_form.extend(_content_form.split(boundary_split))
        except:
            list_content_form.append(_content_form)
            print('this flow consist only form')
        list_result=[]
        for it in range(0,len(list_content_form)):
            _content_=list_content_form[it]
            header_form=_content_[:_content_.index(b"\r\n\r\n")+4]
            if header_form is None:
                print('not in form'); return
            header_form_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", header_form.decode("utf8")))
            if 'Content-Disposition' in header_form_parsed.keys() and \
                'filename' in header_form_parsed['Content-Disposition']:
                filename=header_form_parsed['Content-Disposition'].split('filename=')[1].strip('"')
                print(len(_content_[_content_.index(b"\r\n\r\n")+4:]))
                try:
                    if it<len(list_content_form)-1:
                        payload_form=_content_[_content_.index(b"\r\n\r\n")+4:]
                    else:
                        payload_form=_content_[_content_.index(b"\r\n\r\n")+4:_content_.index(boundary_last)]
                    print('Having %s byte of file %s was transmitted from %s to %s'%(len(payload_form),filename,_key.split('=>')[0],_key.split('=>')[1]))
                    
                    file_path = output_path + "/" + '%s_%s'%(datetime.now().strftime('%s'),filename)
                    fd = open(file_path, "wb")
                    fd.write(payload_form)
                    fd.close()
                    print('the file is written in %s'%file_path)
                    if len(payload_form)>0:
                        list_result.append((_key.split('=>')[0],_key.split('=>')[1],len(payload_form),filename,file_path))
                except:
                    print('Have a failure in process effort  processing the file')
        return list_result