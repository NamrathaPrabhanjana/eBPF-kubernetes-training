
FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /

COPY helloworld.py .

ENTRYPOINT python3 helloworld.py
