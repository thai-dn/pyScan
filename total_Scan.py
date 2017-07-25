from Genaral_Port import *
from OS import *
OS_DB_CREATE()

list_port=[]
dict_port={}
general_port(dict_port,list_port)

import re
import socket

import argparse
import logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #This is supress scapy warnings

from scapy.all import *
conf.verb=0 # enable verbose mode - Is this actually working?
conf.nofilter=0





class MAC_ADDRESS_CLASS:
     def __init__(self):
          global MAC_LIST
          f2=open('MAC_ADDRESS_DB.txt','r')
          MAC_LIST=f2.read().split('\n')       

     def MAC_ADDRESS(self,mac_Address):
          self.MAC=mac_Address.strip().split(':')
          MAC=str(self.MAC[0])+str(self.MAC[1])+str(self.MAC[2])
          for M in MAC_LIST:
               if re.search(MAC,M, re.IGNORECASE):
                    return M.split('		')[1].strip()



def MAC_DISCOVER(host,timeout):
	p = sr1(ARP(op=ARP.who_has,pdst=host),timeout=timeout)
        if p is not None: return p.hwsrc


def SYN_scan(dst_ip,dst_port,dst_timeout):
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=dst_timeout)
    if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
        return "Filtered"
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(dport=dst_port,flags="R"),timeout=dst_timeout)
            return "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


live_host=[]

M=MAC_ADDRESS_CLASS()

showport="""
----------------------------
Port\tState\tService'
----------------------------
"""

no=0;
timeout=0.1
d_ip='192.168.1.'
intro="""


           SCAN & Exploit Vulnerability NETWORK DEMO V1.69
					  


"""

mac_show="""

--------------------------------------------------------------------
|HOST\t\tName\t\tMAC-ADDRESS\t\tCompany\t   |
--------------------------------------------------------------------
"""



print intro


lst=[9000,21,22,23,25,53,67,80,135,136,137,138,139,443,445,554,912,3389,5357,5337]
for i in range(1,52):
	print mac_show
	 	
	open_port=[]
	host=d_ip+str(i)
	print host	
	get_mac=MAC_DISCOVER(host,timeout)
	if get_mac:
		MAC=M.MAC_ADDRESS(get_mac)
		try:
			NAME=socket.gethostbyaddr(host)[0]

		except:
			NAME='\t'

		print host,'\t',NAME,'\t',get_mac,'\t',MAC,'\n'
		if no==0: print showport
          	for p in lst:
	       		if p<9500:
	            		port=str(p)
	            		state=SYN_scan(host,p,timeout)
	            		if state== "Open":
					if port in dict_port:
                         			print p,'\t',state,'\t',dict_port[port]
					else: print p,'\t',state
					open_port.append(i)
		live_host.append([host,open_port])

	no=no+1

	#scan OS
	dst_timeout=0.01
	print '\n--------------------------------------------------------------------'
        print 'OS\tVERSION\tPLATFORM\tTOS\tTTL\tDF\tWINDOW'
	print '--------------------------------------------------------------------\n'
        if len(open_port)>0:	
            for dst_port in open_port:
   	        #print dst_port
	        OS_scan(host,dst_port,dst_timeout)






