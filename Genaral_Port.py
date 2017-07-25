#this script will get datasheet port and name
s=''
dict_port={}
list_port=[]
f2=open('port_name.txt','r')
f2.readline()
def general_port(dict_port,list_port):
     for i in f2:
          z=i.strip().split(':')
          port=z[1].strip()
          name=z[0].strip()
          if name=='':
               if z[2]!='':
                    name=z[2]
               else:
                    name='Unknow'
                    
          if len(port)>5:
               range_port=port.split('-')
               #print range_port         
               range_port=range(eval(range_port[0]),eval(range_port[1])+1)
               for k in range_port:
                    dict_port[k]=name
		    list_port.append(k)
	  else:
               dict_port[port]=name
	       list_port.append(eval(port))
