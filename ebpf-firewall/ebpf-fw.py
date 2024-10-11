# Write a user land bcc python program for ebpf-fw.c

# This is a simple example of how to write a user land bcc python program for ebpf-fw.c. The ebpf-fw.c is a simple eBPF program that can be used to filter packets based on the source and destination IP addresses. 
# The user land bcc python program will load the eBPF program and attach it to a network interface.

# It should be attached to cgroup_skb/ingress and cgroup/egress

from bcc import BPF
import ctypes
import sys
import socket
import struct

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0] 

def main(args):
    b = BPF(src_file="ebpf-fw.c")

    fn = b.load_func("ingress_fn", BPF.CGROUP_SKB)
    cgroup_fd = open("/sys/fs/cgroup", os.O_RDONLY).fileno()
    b.attach_func(fn, cgroup_fd, BPF.CGROUP_INET_INGRESS)

    fn = b.load_func("egress_fn", BPF.CGROUP_SKB)
    b.attach_func(fn, cgroup_fd, BPF.CGROUP_INET_EGRESS)
    
    if args.__len__() == 1:
        print("Running the program in the background")
        b.trace_print()
    else:
        to_block_list = args[1:]
        index = 0
        for eachip in to_block_list:
            ipaddress = eachip
            b["blocked_map"][ctypes.c_uint(index)] = ctypes.c_uint(ip_to_int(ipaddress))       
            print("Blocking IP address: " + ipaddress)
            index += 1
    try:
        print("Monitoring packets")
        while True:
            for i in range(64):
                ip_as_int = b["blocked_map"][ctypes.c_uint(i)].value
                if ip_as_int != 0:
                    print("Blocked IP address: " + socket.inet_ntoa(struct.pack("!I", ip_as_int)))
            sleep(30)
    except KeyboardInterrupt:
        print("exiting")
        os.close(cgroup_fd)
        sys.exit(0)
      
        

# Read command line arguments
if __name__ == "__main__":
    main(sys.argv)
    
# Run the program
# sudo python ebpf-fw.py
