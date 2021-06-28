from scapy.all import *
from arp import arp
from dnsfinal import dnsfinal
from Tkinter import*
import threading

root = Tk()
root.geometry('800x800')
root.configure(background='#F0F8FF')
root.title('ARP_DNS_TOOL')



#variables
#selected mode that the program will perform (arp or dns)
mode = ""
#selected interface to use
interface = ""

def initiate_attack():
    proc_thread = None
    if mode == "arp":
        process = arp(interface, root)
        process.getInput()
    elif mode == "dns":
        process = dnsfinal(interface)
        process.getInput()
        process.startProcess()
    else:
        print("fuck")


def int_selection(modeType):
    global interface
    interface = modeType
    for widget in root.winfo_children():
        widget.destroy()
    initiate_attack()


def select_mode():
    Label(root, text='Select the interface that you want to use').pack()
    OPTIONS = get_if_list()  # etc
    selectMode = Listbox(root, selectmode="single", width=100)
    for each_item in range(len(OPTIONS)):
        selectMode.insert(END, OPTIONS[each_item])
    selectMode.pack()

    def get_selection():
        allItems = selectMode.get(0, END)  # tuple with text of all items in Listbox
        selIdx = selectMode.curselection()  # tuple with indexes of selected items
        selList = [allItems[item] for item in selIdx]
        selectedMode = selList[0]
        int_selection(selectedMode)

    Button(root, text="Execute", command=get_selection).pack()



def on_dns_button():
    list = root.place_slaves()
    for l in list:
        l.destroy()
    global mode
    mode = "dns"
    select_mode()


def on_arp_button():
    for widget in root.winfo_children():
        widget.destroy()
    global mode
    mode = "arp"
    select_mode()

entry = Label(root, text='Welcome to our tool. Please select the attack').place(relx=0.5, rely=0.02, anchor='center')
dnsButton = Button(root, text="Execute DNS attack", command=on_dns_button).place(relx=0.6, rely=0.1, anchor='center')
arpButton = Button(root, text="Execute ARP poisoning", command=on_arp_button).place(relx=0.4, rely=0.1, anchor='center')

root.mainloop()
