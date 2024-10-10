FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

RUN sudo apt-get install -y curl netcat

# nspr4 is a library which exposes low-level ops like I/O, threading etc.
# the sslsniff.py will hook into PR_write() call for intercepting SSL writes.
RUN sudo apt-get install -y libnspr4 libnspr4-dev

WORKDIR /



