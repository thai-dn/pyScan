import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #This is supress scapy warnings

from scapy.all import *
conf.verb=0 # enable verbose mode - Is this actually working?
conf.nofilter=1

list_OS=[]     #create list OS db
def OS_DB_CREATE():
     #OS,VER,PLATFORM,TTL,WINDOW,DF,TOS=0
     
     f2=open('os_DB.txt','r')
     f2.readline()
     
     #print 'OS\t\tVERSION\t\tPLATFORM\tTTL\tWINDOW\tDF\tTOS'     
     for i in f2:
          if '#' not in i and i!='':
               z=i.strip().split()
               
               OS=       z[0]           #OPERATING SYSTEM
               VER=      z[1]           #VERSION
               PLATFORM= z[2]           #PLATFORM
               
               TTL=      eval(z[3])
               
               #WINDOW
               if '-' in z[4]:
                    WINDOW=z[4].split('-')
                    WINDOW=range(eval(WINDOW[0]),eval(WINDOW[1])+1)
               else:
                    WINDOW=   eval(z[4])
               
               #DF
               DF=0
               if z[5]=='y': DF=2
               
               #TOS              
               TOS=      eval(z[6])
               
               lst=list([OS,VER,PLATFORM,TTL,WINDOW,DF,TOS])
               list_OS.append(lst)                               #add to list
               
               #print OS,'\t\t',VER,'\t\t',PLATFORM,'\t',TTL,'\t',WINDOW,'\t',DF,'\t',TOS

def os_fingerprint(TOS_,TTL_,DF_,WINDOW_,list_OS):
     OS=       0
     VER=      1
     PLATFORM= 2
     TTL=      3
     WINDOW=   4
     DF=       5
     TOS=      6

     for i in range(len(list_OS)):
          TOS_FLAG=     False
          TTL_FLAG=     False
          DF_FLAG=      False
          WINDOW_FLAG=  False

          if TTL_ == list_OS[i][TTL]:
	       TTL_FLAG=True

          if TOS_ == list_OS[i][TOS]:
	       TOS_FLAG=True

          if DF_ == list_OS[i][DF]:
	       DF_FLAG=True
	  
	  if 'int' in str(type(list_OS[i][WINDOW])):
               if WINDOW_ == list_OS[i][WINDOW]: WINDOW_FLAG=True
          elif WINDOW_ in list_OS[i][WINDOW]: WINDOW_FLAG=True

	  else: continue
	   #print list_OS[i][6]


          if TOS_FLAG and TTL_FLAG and DF_FLAG and WINDOW_FLAG:
               print list_OS[i][OS],'\t',list_OS[i][VER],'\t',list_OS[i][PLATFORM],'\t',TOS_,'\t',TTL_,'\t',DF_,'\t',WINDOW_

          elif TOS_FLAG and TTL_FLAG and DF_FLAG:
	       print list_OS[i][OS],'\t',list_OS[i][VER],'\t',list_OS[i][PLATFORM],'\t',TOS_,'\t',TTL_,'\t',DF_,'\t',WINDOW_

          elif TOS_FLAG and TTL_FLAG:
	       print list_OS[i][OS],'\t',list_OS[i][VER],'\t',list_OS[i][PLATFORM],'\t',TOS_,'\t',TTL_,'\t',DF_,'\t',WINDOW_
          
	  elif TTL_FLAG:
	       print list_OS[i][OS],'\t',list_OS[i][VER],'\t',list_OS[i][PLATFORM],'\t',TOS_,'\t',TTL_,'\t',DF_,'\t',WINDOW_


def OS_scan(dst_ip,dst_port,dst_timeout):       
     p = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=dst_timeout)
     try:
          #print '\ntos:', p.tos,
          #print 'ttl:', p.ttl,
          #print 'flags:', p.flags,
          #print 'window:', p.window,'\n'
          os_fingerprint(p.tos,p.ttl,p.flags,p.window,list_OS)

     except: pass #print "Fail!!"
if __name__=='__main__':
     OS_DB_CREATE()
     #print 'OS\tVERSION\tPLATFORM\tTOS\tTTL\tDF\tWINDOW'
     lst_=[500,20,21,22,23,25,53,80,135,136,137,138,139,443,445,3389,42050]
     dst_timeout=0.01 
     
     for i in range(1,8):
          dst_ip='192.168.1.'+str(i)
          print 'IP',dst_ip
          for dst_port in lst_:
               OS_scan(dst_ip,dst_port,dst_timeout)




