#!/usr/bin/python
 
import pcapy, sys, random, threading, urllib
from impacket import ImpactDecoder
from scapy.all import *
from optparse import OptionParser

'''
        filternet.py
        Use: filternet.py [hosts file] [outfile file] [trigger]
        -------------------------------------------------
        Host: a structure for maintaining data structures
        current:
        target:
'''

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

        if tcp_hdr.get_RST():
                source_ip = ip_hdr.get_ip_src()
                dest_ip = ip_hdr.get_ip_dst()
                print "Scanning (" + current.address + ") -- " + "RST detected: %s -> %s, ttl: %s" % (source_ip, dest_ip, ip_hdr.get_ip_ttl())
                return

# Open our pcap session

sniff = pcapy.open_live("eth0", 1500, 1, 100)
sniff.setfilter('ip proto \\tcp')

#thread = watchThread(sniff);
#thread.start()

target = Host()
target.address  = "www.balatarin.com"
target.host     = "www.balatarin.com"

current = target

if options.stateless:
        #packet = IP(dst=target.address)/TCP(dport=80,flags='PA',ack=6785,seq=1)/Raw("GET / HTTP/1.0\nHost: " + target.host + "\r\n\r\n")
        #sr1(packet, verbose=0)
        print "stateless"
else:
        f = urllib.urlopen('http://' + target.address)
        print 'Code: ' + str(f.getcode())
        f.close()

target.traceroute,_ = traceroute(target.address, dport=80, maxttl=64, verbose=0)

print target.traceroute.get_trace().values()[0]

#thread.join()



