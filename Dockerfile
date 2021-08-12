FROM ubuntu:20.04 AS stage1
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y python3 cmake lsb-release wget software-properties-common libboost-dev libssl-dev libboost-system-dev libpthread-stubs0-dev libunwind-dev
RUN wget -qO- https://apt.llvm.org/llvm.sh | bash -s -- 12 && \
    apt-get install -y clang-12 libc++-12-dev libc++abi-12-dev
COPY . /src
ENV CXX=clang++-12
RUN cd /src && mkdir build && cd build && cmake .. -DSTATIC=ON && make -j`nproc --all` && mkdir /app && cp rdpproxy /app
