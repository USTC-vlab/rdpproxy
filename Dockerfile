FROM ubuntu:21.10 AS stage1
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y build-essential python3 cmake lsb-release wget \
        software-properties-common libboost-dev libssl-dev libboost-system-dev \
        libpthread-stubs0-dev libunwind-dev zlib1g-dev libvterm-dev meson bison libxml2-dev pkg-config
RUN cd ~ && \
    wget https://github.com/FreeRDP/FreeRDP/releases/download/2.4.1/freerdp-2.4.1.tar.gz && \
    tar xzvf freerdp-2.4.1.tar.gz && \
    cd freerdp-2.4.1 && \
    cmake -DWITH_SERVER=ON -DWITH_CLIENT=OFF -DWITH_PROXY=OFF -DWITH_SHADOW=OFF -DBUILD_SHARED_LIBS=OFF \
        -DWITH_X11=OFF -DWITH_WAYLAND=OFF -DBUILTIN_CHANNELS=OFF -DWITH_CHANNELS=OFF . && \
    make -j`nproc --all` && \
    make install && \
    cd ~ && \
    rm -rf freerdp-2.4.1.tar.gz freerdp-2.4.1
RUN cd ~ && \
    wget https://xkbcommon.org/download/libxkbcommon-1.3.1.tar.xz && \
    tar xvf libxkbcommon-1.3.1.tar.xz && \
    cd libxkbcommon-1.3.1 && \
    meson setup build --default-library=static -Denable-x11=false -Denable-wayland=false \
        -Denable-docs=false && \
    ninja -C build && \
    ninja -C build install && \
    cd ~ && \
    rm -rf libxkbcommon-1.3.1.tar.xz libxkbcommon-1.3.1
RUN cd ~ && \
    wget https://github.com/nemtrif/utfcpp/archive/refs/tags/v3.2.1.tar.gz && \
    tar xvf v3.2.1.tar.gz && \
    cd utfcpp-3.2.1 && \
    cmake -DUTF8_TESTS=OFF . && \
    make install && \
    cd ~ && \
    rm -rf v3.2.1.tar.gz utfcpp-3.2.1
COPY . /src
RUN cd /src && mkdir build && cd build && cmake .. -DSTATIC=ON && make -j`nproc --all` && mkdir /app && cp rdpproxy /app
