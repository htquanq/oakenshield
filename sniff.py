#!/usr/bin/python

from scapy.all import *
import netifaces, threading, logging, time, urllib, re
import logging.handlers as handlers

LOG_DIR= "/tmp/"
RULE_FILE="/data/capstone1/oakenshield/rules.txt"
DATE=time.strftime("/%Y/%m/")
LOG_FILE= time.strftime("%d.log")
INTERFACE=""
PACKETS=dict()
rules=[]

def all_nics():
	return netifaces.interfaces()

def pkt_test(pkt):
	match_pattern

def url_decode(payload):
	return urllib.unquote(payload).decode('utf8')

def read_rule():
	with open(RULE_FILE) as f:
		lines = f.readlines()
		for line in lines:
			rules.append(line.rstrip("\r\n"))

def match_pattern(payload):
	pattern=r"(\'|\"| )|([\w|\'|\"]+[\'|\"|\;| |+|\#|])|(\-\-|\#|\;)"
	result=re.match(pattern, payload)
	if result != None:	
		for group in re.match(pattern, payload).groups():
			print payload

def pkt_callback(pkt):
	create_log_folder(INTERFACE)
	if IP in pkt:
		if pkt["IP"].get_field('proto').i2s[pkt.proto] == "icmp":
			pingOfDeath(pkt["IP"])
		# TCP packets
		# Can be SQLi or Nmap scanner
		# Detect NMap SYN Stealth scan for opened port and closed port
		elif pkt["IP"].get_field('proto').i2s[pkt.proto] == "tcp":
			tcp_pkt = pkt["TCP"]
			src_ip = pkt["IP"].src
			src_dest = pkt["IP"].dst
			src_port = tcp_pkt.sport
			dst_port = tcp_pkt.dport
			flags = tcp_pkt.flags
			seq = tcp_pkt.seq
			ack = tcp_pkt.ack
			# First request is SYN
			# Nmap scan for open port
			# SYN.seq: n (n is integer)
			# SYN/ACK.ack = n + 1
			# R.seq = n + 1

			#Nmap scan for closed port
			# SYN.seq: n (n is integer)
			# RA.ack: SYN.seq(n) + 1
			if flags == "S":
				PACKETS[seq] = tcp_pkt
			elif (flags=="SA") and (ack - 1 in PACKETS) and (src_port == PACKETS.get(ack - 1).dport):
				PACKETS[ack] = tcp_pkt
				PACKETS.pop(ack - 1)
			elif (flags=="RA") and (ack - 1 in PACKETS) and (dst_port == PACKETS.get(ack - 1).sport):
				PACKETS.pop(ack - 1)
				log="%s -> %s. Detected SYN Stealth scan for closed port %s." %(src_ip, src_dest, src_port)
				name="SYN Stealth Scan"
				log_to_file(INTERFACE, log, name)
			elif (flags=="R") and (seq in PACKETS) and (src_port == PACKETS[seq].dport):
				PACKETS.pop(seq)
				log="%s -> %s. Detected SYN Stealth scan for opened port %s." % (src_ip, src_dest, dst_port)
				name="SYN Stealth Scan"
				log_to_file(INTERFACE, log, name)
	#Detect sql injection
	if Raw in pkt:
		data = pkt["Raw"].load
		http_method = data.split("\n")[0]
		if "GET" in http_method:
			payload = http_method.split(" ")[1]
			if payload.startswith("/?"):
				args=payload.split("/?")[1].split("&")
				for arg in args:
					match_pattern(url_decode(arg).split("=")[1])

		if "POST" in http_method:
			payload_length=len(data.split("\n"))
			payload = data.split("\n")[payload_length-1].split("&")
			for arg in args:
				match_pattern(url_decode(arg).split("=")[1])
			
def pingOfDeath(packet):
	# Detect attempt to perform ping of death base on data size
	# If packet size is more than 1500 bytes, log it
	if packet.len > 1500:
		ip_src=packet.src
		ip_dst=packet.dst
		log="%s -> %s Size: %s " %(ip_src, ip_dst, str(packet.len))
		name="Ping Of Death"
		log_to_file(INTERFACE,log, name)

def create_log_folder(interface):
	path = LOG_DIR + str(interface) + DATE
	if not os.path.exists(path):
		os.makedirs(path)
	if not os.path.isfile(path+LOG_FILE):
		file = open(path+LOG_FILE, "w+")
		file.close()

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
	#nics=all_nics()
	#for interface in nics:
	#	INTERFACE=str(interface)
	#	create_log_folder(INTERFACE)
	#	th = threading.Thread(
    #  		target=sniff(iface=INTERFACE, prn=pkt_callback, filter="", store=0)
    #	)
	#	th.start()
	INTERFACE="lo"
	read_rule()
	sniff(iface=INTERFACE,prn=pkt_callback,filter="", store=0)