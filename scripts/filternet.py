#!/usr/bin/python26
 
import pcapy, sys, random, threading, urllib
from impacket import ImpactDecoder
from scapy.all import *
from optparse import OptionParser

'''
        filternet.py
        -------------------------------------------------
		Iterates through a list of hosts to attempt to trigger
		content restrictions or firewalls, then examines:
			
			1.) TCP Resets,
			2.) ICMP Echos,
			3.) HTTP Responses
		
		For TTLs that may give away the position of filtering
		devices.
		
		Acknowlegments:
'''

'''
		Less Friendly Configuration Options
'''

default_device	= 'eth0'
default_ttl		= 64


usage = "usage: %prog [options]"
parser = OptionParser(usage)
parser.add_option("-i", "--input", dest="input_filename", help="read host list from FILENAME")
parser.add_option("-o", "--output", dest="output_filename", help="output host list to FILENAME")
parser.add_option("-s", "--stateless", dest="stateless", action="store_true", help="stateless request, rather than full dance")
parser.add_option("-v", "--verbose", action="store_true", dest="verbose")
(options, args) = parser.parse_args()

if options.input_filename == '':
        parser.print_help()

class Host:
        address = ''
        host    = ''
        traceroute = ''

class watchThread(threading.Thread):
     def __init__(self,sniff):
        threading.Thread.__init__(self)
        self.sniff = sniff;
     def run(self):
        self.sniff.loop(0, callback)
 
def callback(header, data):
        global current

        decoder = ImpactDecoder.EthDecoder()
        ethernet_pck = decoder.decode(data)

        ip_hdr = ethernet_pck.child()
        tcp_hdr = ip_hdr.child()

                source_ip = ip_hdr.get_ip_src()
                dest_ip = ip_hdr.get_ip_dst()

        if tcp_hdr.get_RST():                
                print "TCP Reset Received: Around IP:  [ttl: %s]  (Scanning: %s)" % (source_ip, ip_hdr.get_ip_ttl(), current.address)                

		print tcp_hdr
        '''
        if ICMP Permission Denied:                
                print "ICMP Permission Denied Received: Around IP:  [ttl: %s]  (Scanning: %s)" % (source_ip, ip_hdr.get_ip_ttl(), current.address)                
        if Blocked Page:                
                print "HTML Response Received: Around IP:  [ttl: %s]  (Scanning: %s)" % (source_ip, ip_hdr.get_ip_ttl(), current.address)                
        '''
		return

try:
	
	sniff = pcapy.open_live(default_device, 1500, 1, 100)
	sniff.setfilter('ip proto \\tcp or \\udp or \\icmp')
	
	thread = watchThread(sniff);
	thread.start()
	
	target = Host()
	input_line = "balatarin.com, balatarin.com"
	(target.address, target.host)  = input_line.split(',')
	
	if target.host == '':
	target.host = target.address
	
	current = target
	
	if options.stateless:
		#packet = IP(dst=target.address)/TCP(dport=80,flags='PA',ack=6785,seq=1)/Raw("GET / HTTP/1.0\nHost: " + target.host + "\r\n\r\n")
		#sr1(packet, verbose=0)
		print "stateless"
	else:
		f = urllib.urlopen('http://' + target.address)
		print 'HTTP Response Code for %s: %s' + (target.address, str(f.getcode()))
		f.close()
	
	target.traceroute,_ = traceroute(target.address, dport=80, maxttl=default_ttl, verbose=0)
	
	print target.traceroute.get_trace().values()[0]
	print target.traceroute.get_trace().values()[0][1][0]
	
	thread.join()
except KeyboardInterrupt:
	print 'shutting down'	


