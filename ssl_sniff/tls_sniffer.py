#!/usr/bin/python3

from bcc import BPF
import socket
import os
import sys
from time import sleep
import ctypes as ct

b = BPF(src_file="tls_sniffer.c")

   def handle_tls_event(cpu, data, size):
        class TLSEvent(ct.Structure):
            _fields_ = [("address", ct.c_uint32),
                        ("port", ct.c_uint16),
                        ("tls_version", ct.c_uint16),
                        ("comm", ct.c_char * 64),
                        ("message", ct.c_uint8 * 64),
                        ("message_length", ct.c_uint32),
                        ("pid", ct.c_uint32),
                        ("is_read", ct.c_uint32)]

        # Map the data from kernel to the structure
        tls_event = ct.cast(data, ct.POINTER(TLSEvent)).contents

        # Get TLS information
        pid_to_delete = None
        master_secret = None
        ciphersuite = None
        client_random = None
        bpf_map_tls_information = bpf_handler["tls_information_cache"]
        for pid, tls_info in bpf_map_tls_information.items_lookup_batch():
            if pid.value == tls_event.pid:
                ciphersuite = tls_info.ciphersuite.decode("ascii", "ignore")
                master_secret = binascii.hexlify(tls_info.master_secret)
                master_secret = master_secret.decode("ascii", "ignore")
                client_random = binascii.hexlify(tls_info.client_random)
                client_random = client_random.decode("ascii", "ignore")
                pid_to_delete = [pid]
                break

        # Delete pid from the eBPF map
        if not pid_to_delete:
            bpf_map_tls_information.items_delete_batch(pid_to_delete)

        # Unpack the IPv4 destination address
        addr = struct.pack("I", tls_event.address)

        # Display the TLS event
        if tls_event.is_read:
            print("->", end=" ")
        else:
            print("<-", end=" ")
        print("%s (%d)" % (tls_event.comm.decode("ascii", "replace"),
                           tls_event.pid), end=" ")
        print("%s/%d" % (socket.inet_ntop(socket.AF_INET, addr),
                         socket.ntohs(tls_event.port)), end=" ")

        version = (tls_event.tls_version & 0xF) - 1
        print("TLS1.%d %s" % (version, ciphersuite))

        # Display the message content in hexadecimal
        if tls_event.message_length:
            hex_message = hexdump(tls_event.message[:tls_event.message_length],
                                  dump=True)
            print("\n   ", end="")
            print(hex_message.replace("\n", "\n   "))
            print()


b["tls_events"].open_perf_buffer(handle_tls_event)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting...")
    sys.exit(0)
except Exception as e:
    print(e)

