FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

RUN sudo apt-get install -y hping3

WORKDIR /

COPY ddos_attack.py .

ENTRYPOINT python3 ddos_attack.py

