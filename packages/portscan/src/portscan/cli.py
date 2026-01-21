import subprocess
from contextlib import contextmanager
from scapy.all import *
import random
import time
import socket

def block_rst(sport: int, dport: int):
    subprocess.run(
        ["iptables", "-A", "OUTPUT",
         "-p", "tcp",
         "--tcp-flags", "RST", "RST",
         "--dport", str(dport),
         "--sport", str(sport),
         "-j", "DROP"],
        check=True
    )

def unblock_rst(sport: int, dport: int):
    subprocess.run(
        ["iptables", "-D", "OUTPUT",
         "-p", "tcp",
         "--tcp-flags", "RST", "RST",
         "--dport", str(dport),
         "--sport", str(sport),
         "-j", "DROP"],
        check=True
    )

@contextmanager
def rst_context(sport, dport):
    block_rst(sport, dport)
    yield
    unblock_rst(sport, dport)

def main():

    sport = random.randint(32768, 60999)
    dport = 443
    seq = random.getrandbits(32)
    ts = int(time.time() * 1000)
    
    ip = IP(src="192.168.1.196", dst="185.15.58.224")
    
    syn = ip/TCP(
        seq=seq,
        sport=sport,
        dport=dport,
        flags="S",
        window=64240
    )

    with rst_context(sport, dport):
        synack = sr1(syn, retry=0, verbose=True)

        ack = ip/TCP(
            sport=sport,
            dport=dport,
            flags="A",
            seq=synack.ack,
            ack=synack.seq+1,
        )
        send(ack)
