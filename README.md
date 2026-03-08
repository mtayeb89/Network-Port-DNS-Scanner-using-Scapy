A beginner-friendly Python script that demonstrates two common
network reconnaissance techniques using the Scapy library:

  1. **SYN Scan** — Checks which TCP ports are open on a target host
     by sending SYN packets and listening for SYN-ACK replies.

  2. **DNS Scan** — Checks whether a host is acting as a DNS server
     by sending a DNS query and checking for a response.

Author  : INFOSEC Skills (educational example)
License : MIT
Requires: Python 3.x, Scapy  →  pip install scapy

⚠️  LEGAL NOTICE
-----------------
Only scan hosts you own or have explicit written permission to test.
Unauthorised port scanning may be illegal in your jurisdiction.

-----------------------------------------------------------------
QUICK START
-----------------------------------------------------------------
1. Install Scapy:
      pip install scapy

2. Run the script (root/admin privileges are required by Scapy
   to craft raw packets):
      sudo python3 PortScan.py

3. Change the `host` variable at the bottom of this file to
   target a different IP address.
