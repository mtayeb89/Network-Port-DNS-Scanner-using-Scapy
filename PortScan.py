"""
PortScan.py — Network Port & DNS Scanner using Scapy
=====================================================

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
-----------------------------------------------------------------
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from scapy.all import *   # Gives us IP, TCP, UDP, DNS, DNSQR, sr(), etc.


# ---------------------------------------------------------------------------
# Configuration — ports to probe during the SYN scan
# ---------------------------------------------------------------------------
ports = [25, 80, 53, 443, 445, 8080, 8443]
"""
Common port reference:
  25   — SMTP  (email sending)
  80   — HTTP  (plain-web traffic)
  53   — DNS   (domain name resolution)
  443  — HTTPS (encrypted-web traffic)
  445  — SMB   (Windows file sharing)
  8080 — HTTP  (alternative / proxy)
  8443 — HTTPS (alternative / dev)
"""


# ---------------------------------------------------------------------------
# Function 1: SYN Scan
# ---------------------------------------------------------------------------
def SynScan(host: str) -> None:
    """
    Perform a TCP SYN scan against a list of well-known ports.

    How it works
    ------------
    A SYN packet is the very first step of the TCP three-way handshake.
    When we send a SYN to a port:
      • Open port   → the host replies with SYN-ACK  ✔
      • Closed port → the host replies with RST       ✘
      • Filtered    → no reply (firewall drops it)    …

    We send SYN packets to ALL ports at once using Scapy's sr()
    (send-and-receive), then inspect which ones got a reply whose
    source port matches the destination port we sent to.

    Parameters
    ----------
    host : str
        IPv4 address of the target machine (e.g. "8.8.8.8").

    Notes
    -----
    * sport=5555  → our fake source port (can be any unused port)
    * flags="S"   → 'S' means SYN
    * timeout=2   → wait up to 2 seconds for replies
    * verbose=0   → suppress Scapy's noisy output
    """

    # sr() returns two lists:
    #   ans   — packets that received a reply  (answered)
    #   unans — packets that got no reply       (unanswered)
    ans, unans = sr(
        IP(dst=host) / TCP(sport=5555, dport=ports, flags="S"),
        timeout=2,
        verbose=0,
    )

    print(f"\n[*] Open ports at {host}:")

    # Iterate over each (sent, received) pair in the answered list
    for sent, received in ans:
        # sent[TCP].dport  = the port WE targeted
        # received[TCP].sport = the port the HOST replied FROM
        # If they match, the port is open (replied with SYN-ACK)
        if sent[TCP].dport == received[TCP].sport:
            print(f"    [+] Port {sent[TCP].dport} is OPEN")


# ---------------------------------------------------------------------------
# Function 2: DNS Scan
# ---------------------------------------------------------------------------
def DNSScan(host: str) -> None:
    """
    Check whether the target host is a functioning DNS server.

    How it works
    ------------
    We craft a DNS query asking for the A-record of "google.com"
    and send it over UDP to port 53 (the standard DNS port).
    If we get ANY response back, the host is answering DNS queries
    — meaning it is (or at least acts like) a DNS server.

    Parameters
    ----------
    host : str
        IPv4 address of the target machine (e.g. "8.8.8.8").

    Notes
    -----
    * rd=1          → 'Recursion Desired' flag — ask the server to
                      resolve the name on our behalf
    * DNSQR(...)    → DNS Question Record; qname is the domain to query
    * sport=5555    → our source port
    * dport=53      → destination is the DNS port
    """

    ans, unans = sr(
        IP(dst=host) / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com")),
        timeout=2,
        verbose=0,
    )

    # Any answer at all means the host responded to a DNS query
    if ans:
        print(f"\n[*] DNS Server detected at {host}")
    else:
        print(f"\n[-] No DNS response from {host} (port 53 may be closed or filtered)")


# ---------------------------------------------------------------------------
# Entry point — change `host` to your target IP
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Target host — replace with a machine you are authorised to scan
    host = "8.8.8.8"   # Google's public DNS server (safe demo target)

    print("=" * 50)
    print(f"  Scanning target: {host}")
    print("=" * 50)

    SynScan(host)   # Run the TCP SYN port scan
    DNSScan(host)   # Run the DNS server check

    print("\n[*] Scan complete.")
