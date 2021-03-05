from scapy.all import *
import time
import optparse
def TimeStamp2Time(timeStamp):
    timeTmp=time.localtime(timeTmp)
    myTime=time.strtime("%Y-%m-%d %H:%M:%s",timeTmp)
    return myTime
def PackCallBack(packet):
    print("*"*30)
    print("[%s]Source:%s:%s --->Target:%s:%s"%(packet.time,packet[IP].src,packet.sport,packet[IP].dst,packet.dport))
    print(packet.show)
    print("*"*30)



if __name__=='__main__':
    parser = optparse.OptionParser("Ex:python %prog -i 127.0.0.1 -c 5 -o output.pcap\n")
    parser.add_option('-i','--IP',dest='hostIP',default="127.0.0.1",type='string',help='IP address [default=127.0.0.1]')
    parser.add_option('-c','--count',dest='packetCount',default=5,type='int',help='Packet count [default=5]')
    parser.add_option('-o','--output',dest='fileName',default='output.pcap',type='string',help='save filename[default=output.pcap]')
    (options,args)=parser.parse_args()
    defFilter="dst " + options.hostIP
    packets=sniff(filter=defFilter,prn=PackCallBack,count=options.packetCount)
    wrpcap(options.fileName,packets)
