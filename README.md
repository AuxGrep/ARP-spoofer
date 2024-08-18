# ARP-spoofer
ADVANCED ARP spoofer for powerful MITM Attacks 

![Screenshot from 2024-08-17 17-27-17](https://github.com/user-attachments/assets/ab442d6c-578b-4912-a0ac-5136ba43fb8f)
![Screenshot from 2024-08-17 17-34-45](https://github.com/user-attachments/assets/c7b34b92-f20b-4eef-a535-8aa63e25c461)

# ABOUT
An advanced ARP spoofer is a network attack tool or script that performs ARP (Address Resolution Protocol) spoofing in a more sophisticated and effective way. 
ARP spoofing is a technique used by attackers to intercept communication between two devices on a local network, often for purposes like man-in-the-middle attacks, session hijacking, or network monitoring

# FEATURES
1. Multiple Target Spoofing => It can spoof multiple targets simultaneously, allowing it to manipulate traffic between several hosts on the network.
2. Packet Filtering and Injection => It can filter and modify intercepted packets before forwarding them, making them useful for tasks like injecting malicious code or manipulating data in transit.
3. Log POst Data events => It logs all POST data sent by victim in a log file
4. Beef and Other py injection capability => It support third part loader to inject on the traffic such as BEEF
5. User-Friendly Interface and Automation => It typically have user-friendly CLI interfaces, with the ability to automate and script complex attack workflows.

# INSTALL
1. git clone https://github.com/AuxGrep/ARP-spoofer
2. sudo chmod 775 setup-ARP-MITM.sh
3. sudo ./setup-ARP-MITM.sh

# USAGE
1. sudo python3 arp_spoofer.py --help
2. Setup target Manual: sudo python3 arp_spoofer.py
3. One line Usage: sudo python3 arp_spoofer.py -t gateway Victim_ip
   eg: sudo python3 arp_spoofer.py -t 192.168.10.1 192.168.10.170
