from scapy.all import *
import netifaces, threading, logging, time
import logging.handlers as handlers

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
	log_to_file("/tmp/test/test.log",ip_src + str(data), "sqli")

def create_log_folder(interface):
	path = "/tmp/" + interface +time.strftime("/%Y/%m/")
	if not os.path.exists(path):
		os.makedirs(path)
	if not os.path.isfile(path+time.strftime("%d.log")):
		file = open(path+time.strftime("%d.log"), "w+")

def log_to_file(path,payload,name):
    # Set event log name
    logger = logging.getLogger(name)
    # Set log format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
    # Set log file
    fh = logging.FileHandler(path)
    # Set log level
    fh.setLevel(logging.WARN)
    # Set log format
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    # Generate log data
    logger.warn(payload)

if __name__=="__main__":
	nics=all_nics()
	for interface in nics:
		create_log_folder(str(interface))
		#th = threading.Thread(
      #target=sniff(iface=interface, prn=pkt_callback, filter="tcp", store=0)
    #)
	#	th.start()