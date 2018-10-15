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
	create_log_folder("lo")
	#ip_src=pkt[IP].src
	#ip_dst=pkt[IP].dst
	#flags=pkt[TCP].flags
	#tcp_sport=pkt[TCP].sport
	#tcp_dport=pkt[TCP].dport
	pingOfDeath(pkt)
	#packet=synScan(ip_src,ip_dst,tcp_dport,tcp_dport,flags,)


#def synScan(flags, src_ip, dest_port, num):
	# SYN Stealth scan for open port
	# number of packet=3, flag is SSAR
	#if flags=="SSAR" and num==3:

def pingOfDeath(packet):
	# Detect ping packet
	if packet["IP"].get_field('proto').i2s[packet.proto] == "icmp" and packet["IP"].len > 65536:
		ip_src=packet["IP"].src
		ip_dst=packet["IP"].dst
		log="%s -> %s Size: %s " %(ip_src, ip_dst, str(packet["IP"].len))
		name="Ping Of Death"
		log_to_file("lo",log, name)

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
	sniff(iface=INTERFACE,prn=pkt_callback,filter="", store=0)