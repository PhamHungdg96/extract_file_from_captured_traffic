#!/usr/bin/python

import struct
import socket
import requests

def get_mac_addr(bytes_addr):
	#print(bytes_addr)
	bytes_str = map("{:02x}".format, bytes_addr)
	return ':'.join(bytes_str).upper()

def get_ipv4(addr):
	return '.'.join(map(str,addr))

#Ethernet frame
def parse_frame(frame):
	eth_len = 14
	eth_header = frame[:eth_len]
	eth_data = frame[eth_len:]
	dest_mac,src_mac,proto_field1,proto_field2 = struct.unpack('!6s6scc' , eth_header)	
	dest_mac = get_mac_addr(dest_mac)
	src_mac = get_mac_addr(src_mac)

	# proto is of the form b'\x08\x00'
	#print(proto_field1+proto_field2)
	proto1 = ''.join(map(str,proto_field1))
	proto2 = ''.join(map(str,proto_field2))
	proto = proto1+proto2
	#print(proto)
	if proto == '80':
		ip_proto = 'IPv4'
	elif proto == '86':
		ip_proto = 'ARP'
	elif proto == '86DD':
		ip_proto = 'IPv6' 
	else:
		ip_proto = proto
	print('\n\n*********Ethernet Frame*********')
	print("Source_MAC:",src_mac,"\tDestination_MAC:",dest_mac,
		  "\nInternet Protocol:",ip_proto)
	return eth_data,ip_proto


def parse_packet(packet):
	#Contains IP version and Header Length
	first_byte = packet[0]

	#First 4 bits is version
	ip_version = first_byte >> 4
	#Next 4 bits is header_length
	ip_header_length = (first_byte & 15) * 4

	ttl,proto,src,dest = struct.unpack('!8xBB2x4s4s',packet[:20])

	#Ip address in string format..
	src_ip = get_ipv4(src)
	dest_ip = get_ipv4(dest)

	#Reverse dns lookup..
	src_web = rev_dnslookup(src_ip)
	dest_web = rev_dnslookup(dest_ip)

	if proto == 1:
		transport_proto = 'ICMP'
	elif proto == 6:
		transport_proto = 'TCP'
	elif proto == 17:
		transport_proto = 'UDP'
	else:
		transport_proto = 'Unknown Protocol Field = '+str(proto)

	print('---------IP Packet---------')
	print("Source_IP:",src_ip,"\tDestination_IP:",dest_ip,
		  "\nTTL:",ttl,'hops\t','\tTransport_Protocol:',transport_proto)
	return packet[ip_header_length:],transport_proto

def parse_ICMP(data):
	field_type = struct.unpack('!B')
	if field_type == 0:
		ICMP_type = 'Echo Reply'
	elif field_type ==3:
		ICMP_type = 'Destination Unreachable'
	elif field_type ==4:
		ICMP_type = 'Source Quench'
	elif field_type ==5:
		ICMP_type = 'Redirect Message'
	elif field_type ==8:
		ICMP_type = 'Echo Request'
	elif field_type ==9:
		ICMP_type = 'Router Advertisement'
	elif field_type ==10:
		ICMP_type = 'Router Solicitation'
	elif field_type ==11:
		ICMP_type = 'Time Exceeded'
	elif field_type ==12:
		ICMP_type = 'Parameter Problem:Bad IP header'
	elif field_type ==13:
		ICMP_type = 'Timestamp Request'
	elif field_type ==14:
		ICMP_type = 'Timestamp Reply'
	elif field_type ==15:
		ICMP_type = 'Information Request'
	elif field_type ==16:
		ICMP_type = 'Information Reply'
	elif field_type ==17:
		ICMP_type = 'Address Mask Request'
	elif field_type ==18:
		ICMP_type = 'Address Mask Reply'
	elif field_type ==30:
		ICMP_type = 'Traceroute'
	else:
		ICMP_type = 'Reserved or Deprecated'
	print('---------ICMP Packet---------')
	print("Type:",ICMP_type)
	return data[8:]



def parse_UDP(data):
	src_port,dest_port,packet_length = struct.unpack('!HHH',data[:6])
	print('---------UDP Packet---------')
	print("Source_Port:",src_port,"\tDestination_Port:",dest_port,
		  "\nPacket_Length:",packet_length)
	return data[8:]

def parse_TCP(data):
	src_port,dest_port,seq,ack,offset_flags = struct.unpack('!HHLLH',data[:14])
	
	#Extract first 4 bits and multiply by 4 to get the header length.
	tcp_header_length = (offset_flags >> 12) * 4

	#Extract all the flags starting at positon 5 from left and so and with 2^5
	flag_urg = (offset_flags & 32) >> 5
	flag_ack = (offset_flags & 16) >> 4
	flag_psh = (offset_flags & 8) >> 3
	flag_rst = (offset_flags & 4) >> 2
	flag_syn = (offset_flags & 2) >> 1
	flag_fin = offset_flags & 1

	print('---------TCP Packet---------')
	print("Source_Port:",src_port,"\tDestination_Port:",dest_port,
		  "\nHeader_Length:",tcp_header_length)
	print("Sequence:",seq)
	print("Acknowledgement:",ack)
	print("Flags: URG ACK PSH RST SYN FIN")
	print("      {:3}".format(flag_urg),"{:3}".format(flag_ack),"{:3}".format(flag_psh),
				"{:3}".format(flag_rst),"{:3}".format(flag_syn),"{:3}".format(flag_fin))
	return data[tcp_header_length:]

def parse_transport_packet(data,protocol):
	application_packet = None
	if protocol == 'TCP':
		application_packet = parse_TCP(data)
	elif protocol == 'UDP':
		application_packet = parse_UDP(data)
	elif protocol == 'ICMP':
		application_packet = parse_ICMP(data)
	return application_packet
	

def rev_dnslookup(ip_addr):

	#return domain name as a string or 'private_ip' if a private ip
	ip_classes = []
	for x in ip_addr.split('.'):
		ip_classes.append(int(x))

	#Ignore if a private Ip
	if((ip_classes[0] == 10 and (0 <= ip_classes[1]+ip_classes[2]+ip_classes[3] <= 766)) or
		(ip_classes[0] == 172 and (16 <= ip_classes[1] <= 31) and (0 <= ip_classes[2]+ip_classes[3] <= 510)) or
		(ip_classes[0] == 192 and ip_classes[1] == 168 and (0 <= ip_classes[2]+ip_classes[3] <= 510))):
			print('Private IP Address: '+ip_addr)
	else:
		try:
			rdns_data = socket.gethostbyaddr(ip_addr)
			print("Domain Name: "+rdns_data[0])
			print("Host IP: "+rdns_data[2][0])
		except socket.error:
			print("Domain Name not found.")

		# Reverse DNS Api call using requests module to fetch the domain name/website name
		# url = "https://api.viewdns.info/reverseip/?host="+ip_addr+"&apikey=5dd53a2f62db0efec48f8a412199727316ed8684&output=json"
		# response = requests.get(url)
		# rdns_json = json.loads(response)
		# print("Host IP: "+rdns_json['host'])
		# print("Domain Name: "+rdns_json['domains'][-1]['name'])


#*******Main************
def main():
	#Make the socket connection
	conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))

	while True:
		#Receive the ethernet frame
		payload,addr = conn.recvfrom(65535)
		ip_packet,ip_protocol = parse_frame(payload)
		if ip_protocol == 'IPv4':
			transport_packet,transport_proto = parse_packet(ip_packet)
			application_packet = parse_transport_packet(transport_packet,transport_proto)

if __name__=="__main__":
	main()