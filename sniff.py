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

def pkt_test(pkt):
	print pkt.show()

def pkt_callback(pkt):
	opened = []
	closed = []
	create_log_folder(INTERFACE)
	if pkt["IP"].get_field('proto').i2s[pkt.proto] == "icmp":
		pingOfDeath(pkt)
	# TCP packets
	# Can be SQLi or Nmap scanner
	# Detect NMap SYN Stealth scan for opened port and closed port
	else:
		src_port = pkt["TCP"].sport
		dst_port = pkt["TCP"].dport
		flags = pkt["TCP"].flags
		seq = pkt["TCP"].seq
		ack = pkt["TCP"].ack
		# First request is SYN
		# Nmap scan for open port
		# SYN.seq: n (n is integer)
		# SYN/ACK.ack = n + 1
		# R.seq = n + 1

		#Nmap scan for closed port
		# SYN.seq
		if flags == "S":
			opened.append(pkt)
			closed.append(pkt)
		elif (flags=="SA") and (ack == opened[0]["TCP"].seq + 1) and (src_port == opened[0]["TCP"].dport):
			opened.append(pkt)
		elif (flags=="RA") and (ack == opened[0]["TCP"].seq + 1) and (dst_port == closed[0]["TCP"].sport):
			closed.append(pkt)
		elif (flags=="R") and (seq == opened[0]["TCP"].seq + 1) and (dst_port == opened[0]["TCP"].dport):
			opened.append(pkt)


#def synScan(flags, src_ip, dest_port, num):
	# SYN Stealth scan for open port
	# number of packet=3, flag is SSAR
	#if flags=="SSAR" and num==3:

def pingOfDeath(packet):
	# Detect attempt to perform ping of death base on data size
	# If packet size is more than 1500 bytes, log it
	if packet["IP"].len > 1500:
		ip_src=packet["IP"].src
		ip_dst=packet["IP"].dst
		log="%s -> %s Size: %s " %(ip_src, ip_dst, str(packet["IP"].len))
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
	sniff(iface=INTERFACE,prn=pkt_test,filter="", store=0)