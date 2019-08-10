from scapy.all import *
from random import randint
from tcp_snd import Snd
from tcp_rcv import Rcv



is_syn_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == TCP_FLAGS['S']

is_fin_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == TCP_FLAGS['F']

is_finack_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == (TCP_FLAGS['F'] | TCP_FLAGS['A'])

is_synack_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == (TCP_FLAGS['S'] | TCP_FLAGS['A'])

create_pkt_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].src,str(pkt['IP'].sport),pkt['IP'].dst,str(pkt['IP'].dport))

create_forward_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].src,str(pkt['IP'].sport),pkt['IP'].dst,str(pkt['IP'].dport))

create_reverse_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].dst,str(pkt['IP'].dport),pkt['IP'].src,str(pkt['IP'].sport))


create_flow = create_forward_flow


TCP_FLAGS = {"F":0x1, "S":0x2, "R":0x4, "P":0x8,
              "A":0x10, "U":0x20, "E":0x40, "C":0x80,
              0x1:"F", 0x2:"S", 0x4:"R", 0x8:"P",
              0x10:"A", 0x20:"U", 0x40:"E", 0x80:"C"}

TCP_STATES = {"LISTEN":{'S':["SYN_RCVD", 'SA']},
              "SYN_SENT":{'SA':["ESTABLISHED", 'A'],'S':["SYN_RCVD", 'SA'],},
              "SYN_RCVD":{'F':["FIN_WAIT_1", 'A'],'A':["ESTABLISHED", ''],'R':["LISTEN", ''],},
              "LAST_ACK":{},
              "CLOSE_WAIT":{"":["LAST_ACK","F"]}, # initiated by the server
              "LAST_ACK":{"A":["CLOSED",""]},
              "ESTABLISHED":{"F":["FIN_WAIT_1",""],},
              "FIN_WAIT_1":{"A":["FIN_WAIT_2",""],"F":["CLOSED","A"],"FA":["TIME_WAIT","A"],},
              "FIN_WAIT_2":{"F":["TIME_WAIT","A"],},
              "CLOSED":{"A":["TIME_WAIT", ""]},}
                   

flags_equal = lambda pkt, flag: pkt['TCP'].flags == flag
flags_set = lambda pkt, flag: (pkt['TCP'].flags & flag) != 0

class TCPStateMachine:
    def __init__(self, pkt=None):
        if not pkt is None:
            self.init(pkt)
    
    def init(self, pkt):
        if not 'TCP' in pkt:
            raise Exception("Not a TCP Packet")
        if not is_syn_pkt(pkt):
            raise Exception("Not valid SYN")
            
        self.flows = set((create_forward_flow(pkt), create_reverse_flow(pkt)))
        self.server = pkt['IP'].dst
        self.client = pkt['IP'].src
        self.server_port = pkt['TCP'].dport
        self.client_port = pkt['TCP'].sport
        # 0 is now, 1 is the future Flags
        self.server_state = "LISTEN"
        self.client_state = "SYN_SENT"
        
        self.server_close_time = -1.0
        self.client_close_time = -1.0
        self.fin_wait_time = -1.0
        
        
        
    def next_state(self, pkt):
        if not 'TCP' in pkt:
            raise Exception("Not a TCP Packet")
        
        # determine in what context we are handling this packet
        flow = create_flow(pkt)
        if flow not in self.flows:
            raise Exception("Not a valid packet for this model")
        
        if pkt['IP'].dst == self.server and pkt['IP'].src == self.client:
            v =  self.handle_client_pkt(pkt)
            if self.is_fin_wait():
               self.fin_wait_time = pkt.time
            return v
        if pkt['IP'].src == self.server and pkt['IP'].dst == self.client:
            v = self.handle_server_pkt(pkt)
            if self.is_fin_wait():
               self.fin_wait_time = pkt.time
            return v
            
        
        raise Exception("Not a valid packet for this model")
        
    
    def get_states(self):
        return (self.client_state, self.server_state)
        
    
    def build_flags(self, sflags):
        return sum([TCP_FLAGS[i] for i in sflags])
        
    
    def active_close(self):
        # print(self.client_state,self.server_state)
        return (self.client_state == self.server_state and self.server_state == "CLOSED")
    
    def passive_close(self):
        # print(self.client_state,self.server_state)
        return (self.client_state == "LAST_ACK" and self.server_state == "CLOSE_WAIT")
    
    def is_established(self):
        return (self.client_state == self.server_state and self.server_state == "ESTABLISHED")
    
    def client_prehandshake(self):
        return (self.client_state == "SYN_SENT") or (self.client_state == "SYN_RCVD")
    
    def server_prehandshake(self):
        return (self.server_state == "SYN_SENT") or (self.server_state == "SYN_RCVD") or (self.server_state == "LISTEN")
    
    def is_fin_wait(self):
        return self.client_state.find("FIN_WAIT") > -1 or self.server_state.find("FIN_WAIT") > -1
    def is_prehandshake(self):
        return self.client_prehandshake() and self.server_prehandshake()
    
    def is_closed(self):
        return self.passive_close() or self.active_close()
    
    def handle_client_pkt(self, pkt):
        flags = pkt['TCP'].flags
        client_got_closed = False
        server_got_closed = False
        
        if flags == self.build_flags("R"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True

        elif flags == self.build_flags("RA"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True
        elif flags == self.build_flags("S"):
            self.server_state = "SYN_SENT"

        elif self.client_state == "SYN_SENT":
             if flags & self.build_flags("A") > 0:
                 self.client_state = "ESTABLISHED"
                 self.server_state = "ESTABLISHED"
             else:
                 self.client_state = "CLOSED"
                 server_got_closed = pkt.time 
                 client_got_closed = pkt.time
                 return self.is_closed()
            
        elif self.client_state == "SYN_SENT":
            if flags & self.build_flags("SA") > 0:
                self.client_state = "SYN_RCVD"
            
        elif self.client_state == "SYN_RCVD" and\
              flags & self.build_flags("F") > 0:
                self.client_state = "FIN_WAIT_1"

        elif self.client_state == "ESTABLISHED" and\
            flags == self.build_flags("FA"):
            self.client_state = "FIN_WAIT_1"
        
        elif self.client_state == "FIN_WAIT_1" and\
            flags == self.build_flags("A"):
            self.client_state = "CLOSED"
        
        elif self.client_state == "ESTABLISHED" and\
            self.server_state == "CLOSE_WAIT" and\
            flags & self.build_flags("A") > 0:
            self.client_state = "CLOSED"
        
        if self.server_state == "FIN_WAIT_1" and\
            self.client_state == "CLOSED" and\
            flags == self.build_flags("A"):
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True
        
        if client_got_closed:
            self.client_close_timed = pkt.time
        if server_got_closed:
            self.server_close_timed = pkt.time
            
        return self.is_closed()
        
    def handle_server_pkt(self, pkt):
        flags = pkt['TCP'].flags
        server_got_closed = False
        client_got_closed = False

        if flags == self.build_flags("R"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True

        elif flags == self.build_flags("RA"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True

        elif flags == self.build_flags("S"):
            self.server_state = "SYN_SENT"
        elif self.server_state == "LISTEN" and\
            flags == self.build_flags("SA"):
            self.server_state = "SYN_RCVD"
        
        elif self.server_state == "ESTABLISHED" and\
            flags == self.build_flags("FA"):
            self.server_state = "FIN_WAIT_1"
        
        elif self.server_state == "FIN_WAIT_1" and\
            flags == self.build_flags("A"):
            self.server_state = "CLOSED"
            server_got_closed = True

        
        elif self.server_state == "SYN_RCVD" and\
            flags == self.build_flags("F"):
            self.server_state = "FIN_WAIT_1"
        
        elif self.server_state == "FIN_WAIT_1" and\
            flags == self.build_flags("FA"):
            self.server_state = "CLOSED"
            
        elif self.server_state == "SYN_RCVD" and\
            flags == self.build_flags("A"):
            self.server_state = "ESTABLISHED"
        
        elif self.server_state == "ESTABLISHED" and\
            flags & self.build_flags("F") > 0:
            self.server_state = "CLOSE_WAIT"
        
        elif self.client_state == "FIN_WAIT_1" and\
            flags == self.build_flags("FA"):
            self.server_state = "CLOSED"                    
            server_got_closed = True
            
        elif self.client_state == "CLOSED" and\
            flags == self.build_flags("A"):
            self.server_state = "CLOSED"
            server_got_closed = True
                
        if self.client_state == "FIN_WAIT_1" and\
            self.server_state == "CLOSED" and\
            flags == self.build_flags("A"):
            self.client_state = "CLOSED"
            client_got_closed = True
        
        if client_got_closed:
            self.client_close_timed = pkt.time
        if server_got_closed:
            self.server_close_timed = pkt.time

        return self.is_closed()



