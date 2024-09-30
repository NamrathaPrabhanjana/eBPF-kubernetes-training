FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /

COPY udp_blocker_xdp.py .
COPY udp_blocker_xdp.c .

CMD ["python3", "udp_blocker_xdp.py"]

