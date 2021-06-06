from scapy.all import *
from arp import arp
from dnsfinal import dnsfinal

print("--=====-- Welcome to WARP, ARP/DNS poisoning tool --=====--")
time.sleep(0.5)

#variables
#selected mode that the program will perform (arp or dns)
mode = ""
#selected interface to use
interface = ""


#selecting procedure to execute
while(mode != "dns" and mode != "arp"):
    mode = raw_input("Select mode by typing arp or dns: ")
    if(mode != "dns" and mode != "arp"):
        print("Enter a valid input!")

#selecting interface to use
print("Available interfaces: ")
# print the list of available interfaces and print them
print(get_if_list())
#user enters which interface to use
while(not(interface in get_if_list())):
    interface = raw_input("Select the interface that you want to use: ")
    if(not(interface in get_if_list())):
        print("Enter a valid input!")

#calling the process we want to run
if(mode == "arp"):
    process = arp(interface)
    process.getInput()
    process.startProcess()
elif(mode == "dns"):
    process = dnsfinal(interface)
    process.getInput()
    process.startProcess()



