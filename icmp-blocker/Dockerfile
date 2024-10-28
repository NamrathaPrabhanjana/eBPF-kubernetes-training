FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /

COPY icmp_blocker_xdp.py .
COPY icmp_blocker_xdp.c .

#ENTRYPOINT python3 icmp_blocker_xdp.py

ENTRYPOINT bash
