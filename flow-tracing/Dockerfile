FROM ebpf-base-ctr:1.0 as base_os
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get install -y pip

RUN pip install prometheus_client
RUN pip install requests

WORKDIR /

COPY main.py .
COPY prober.c .
COPY prober.py .
COPY kube_crawler.py .

ENTRYPOINT python3 main.py
