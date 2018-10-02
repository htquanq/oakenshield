from scapy.all import *

def pkt_callback(pkt):
	ip_src=""
	ip_dst=""
	tcp_sport=""
	tcp_dport=""
	data=""
	if IP in pkt:
		ip_src=pkt[IP].src
		ip_dst=pkt[IP].dst
	if TCP in pkt:
		tcp_sport=pkt[TCP].sport
		tcp_dport=pkt[TCP].dport
	if TCP in pkt:
		data=pkt[TCP].payload
	print " IP src : " + str(ip_src) + " TCP sport " + str(tcp_sport) + " payload " + str(data)
	print " IP dst : " + str(ip_dst) + " TCP dport " + str(tcp_dport)

sniff(iface="lo", prn=pkt_callback, filter="tcp port 80", store=0)