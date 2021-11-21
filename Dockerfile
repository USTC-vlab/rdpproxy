FROM ubuntu:21.10 AS stage1
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y build-essential python3 cmake lsb-release wget software-properties-common libboost-dev libssl-dev libboost-system-dev libpthread-stubs0-dev libunwind-dev
COPY . /src
RUN cd /src && mkdir build && cd build && cmake .. -DSTATIC=ON && make -j`nproc --all` && mkdir /app && cp rdpproxy /app
