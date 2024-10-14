FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /

COPY runqlat.py .
COPY cpudist.py .

ENTRYPOINT python3 runqlat.py
