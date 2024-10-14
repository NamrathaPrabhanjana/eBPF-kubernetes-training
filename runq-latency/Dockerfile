FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /

COPY cpudist.py .
COPY runqlat.py .

ENTRYPOINT python3 runqlat.py
