FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /

COPY main.py .
COPY prober.c .
COPY prober.py .


