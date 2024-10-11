#!/usr/bin/python3

from bcc import BPF
import socket
import os
import sys
from time import sleep

b = BPF(src_file="icmp_blocker_xdp.c")
interface = "lo"

# xdp will be hit when a packet arrives on the interface
fx = b.load_func("xdp_icmp_blocker", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

try:
    b.trace_print()
except KeyboardInterrupt:
    print("Removing XDP program")
    BPF.remove_xdp(interface, 0)
    sys.exit()
except Exception as e:
    print("Hit an exception: ", e)

# Test using 'netcat -u google.com 443'
