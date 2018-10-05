from scapy.all import *
import netifaces, threading, logging

def all_nics():
	return netifaces.interfaces()

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



if __name__=="__main__":
	nics=all_nics()
	for interface in nics:
		th = threading.Thread(
      target=sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
    )
		th.start()