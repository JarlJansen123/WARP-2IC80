# LabOnOffensiveSecurity

Group project Lab on Offensive Computer Security

To run the project

1. Install Scapy Python library and tkinter Python library

2. Open all 3 virtual machines

2. On the attack m3, open the directory with these files in it in the command prompt

3. Simply write 'sudo python warp.py' and the GUI will open. Do what the GUI says to do

4. *For DNS spoofing to work, you need to make sure that packet forwarding is disabled. If 'sysctl net.ipv4.ip_forward' in Linux command prompt returns 0, everything is good. Otherwise, follow the guide here: https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux
