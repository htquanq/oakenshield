#!/usr/bin/python

from scapy.all import *
import netifaces, threading, logging, time
import logging.handlers as handlers

LOG_DIR= "/tmp/"
DATE=time.strftime("/%Y/%m/")
LOG_FILE= time.strftime("%d.log")
INTERFACE=""

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
		data=pkt[TCP].payload
		if "OR%20" in str(data):
			message = ip_src + " -> " + ip_dst + str(data)
			log_to_file(INTERFACE, message, "sqli")

def create_log_folder(interface):
	path = LOG_DIR + str(interface) + DATE
	if not os.path.exists(path):
		os.makedirs(path)
	if not os.path.isfile(path+LOG_FILE):
		file = open(path+LOG_FILE, "w+")

def log_to_file(interface,payload,name):
	path = LOG_DIR + str(interface) + DATE + LOG_FILE
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
		INTERFACE=str(interface)
		create_log_folder(INTERFACE)
		th = threading.Thread(
      		target=sniff(iface=INTERFACE, prn=pkt_callback, filter="tcp", store=0)
    	)
		th.start()