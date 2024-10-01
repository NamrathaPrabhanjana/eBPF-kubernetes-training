FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /

COPY runq_latency.py .
COPY runq_latency.c .

#ENTRYPOINT python3 runq_latency.py
