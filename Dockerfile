# This is the master dockerfile used to build a base container with all ebpf dependencies in place

FROM ubuntu:20.04 as base_os
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Indian

RUN apt-get update && apt install -y sudo vim

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# install dependencies
RUN sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  	libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  	liblzma-dev arping netperf iperf

WORKDIR /
# for bcc headers, bcc tools, python bcc
RUN	bash -xc " \
	git clone https://github.com/iovisor/bcc.git ; \
	mkdir bcc/build && cd bcc/build ; \
	cmake .. ; \
	make ; \
	sudo make install ; \
	cmake -DPYTHON_CMD=python3 .. ;"

#build python deps
WORKDIR /bcc/build/src/python
RUN	bash -xc "make ; \
	sudo make install ;"

# for bpftool
RUN sudo apt install -y linux-tools-$(uname -r)
RUN sudo apt-get install -y linux-headers-$(uname -r)
# for bpf-related headers
RUN sudo apt-get install -y libbpf-dev 

# Lua JIT
RUN sudo apt-get install -y luajit luajit-5.1-dev

RUN sudo apt install -y net-tools conntrack systemd

WORKDIR /
