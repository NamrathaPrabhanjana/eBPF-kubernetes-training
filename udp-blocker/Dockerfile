FROM ubuntu:20.04 as base_os
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt install -y sudo vim bpfcc-tools python3
RUN apt-get install -y linux-headers-$(uname -r)
RUN apt-get install -y clang llvm libelf-dev libbpf-dev libbpfcc-dev

WORKDIR /

COPY udp_blocker_xdp.py .
COPY udp_blocker_xdp.c .

CMD ["python3", "udp_blocker_xdp.py"]

