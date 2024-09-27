
FROM ubuntu:20.04 as base_os
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt install -y sudo vim bpfcc-tools python3
RUN apt-get install -y linux-headers-$(uname -r)

WORKDIR /

COPY helloworld.py .

ENTRYPOINT python3 helloworld.py
