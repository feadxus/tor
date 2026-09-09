# ==========================================
# 阶段 1: 编译 Go 语言客户端 (Snowflake + Webtunnel + Lyrebird)
# ==========================================
FROM golang:1.24-alpine AS go-builder

WORKDIR /usr/src

# 安装 git
RUN apk add --no-cache git

# ------------------------------------------
# 1.1 编译 Snowflake Client (v2.14.1)
# ------------------------------------------
RUN git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake.git && \
    cd snowflake && \
    git checkout v2.14.1

WORKDIR /usr/src/snowflake/client
RUN CGO_ENABLED=0 go build -v -trimpath -ldflags="-s -w" -o snowflake-client

# ------------------------------------------
# 1.2 编译 Webtunnel Client (v0.0.6)
# ------------------------------------------
WORKDIR /usr/src
RUN git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel.git && \
    cd webtunnel && \
    git checkout v0.0.6

WORKDIR /usr/src/webtunnel/main/client
RUN CGO_ENABLED=0 go build -v -trimpath -ldflags="-s -w" -o webtunnel-client

# ------------------------------------------
# 1.3 编译 Lyrebird Client (obfs4/meek 混淆插件)
# ------------------------------------------
WORKDIR /usr/src
RUN git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git && \
    cd lyrebird && \
    git checkout lyrebird-0.5.0

WORKDIR /usr/src/lyrebird
RUN CGO_ENABLED=0 go build -v -trimpath -ldflags="-s -w" -o lyrebird ./cmd/lyrebird

# ==========================================
# 阶段 2: 编译 C 语言组件 (Tor + Torsocks)
# ==========================================
FROM debian:trixie-slim AS c-builder

ENV DEBIAN_FRONTEND=noninteractive

# 安装 C/Autotools 编译依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    gcc \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config \
    python3 \
    libevent-dev \
    libssl-dev \
    zlib1g-dev \
    libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# ------------------------------------------
# 2.1 编译 Tor (0.4.9.11)
# ------------------------------------------
RUN git clone https://gitlab.torproject.org/tpo/core/tor.git && \
    cd tor && \
    git checkout tor-0.4.9.11

WORKDIR /usr/src/tor
RUN ./autogen.sh && \
    ./configure \
        --prefix=/usr/local \
        --disable-silent-rules \
        --disable-system-torrc \
        --disable-asciidoc \
        --disable-manpage \
        --with-tor-user=debian-tor \
        --with-tor-group=debian-tor \
        --enable-systemd && \
    make -j$(nproc) && \
    make install

# ------------------------------------------
# 2.2 编译 Torsocks (v2.5.0)
# ------------------------------------------
WORKDIR /usr/src
RUN git clone https://gitlab.torproject.org/tpo/core/torsocks.git && \
    cd torsocks && \
    git checkout v2.5.0

WORKDIR /usr/src/torsocks
RUN ./autogen.sh && \
    ./configure \
        --prefix=/usr/local \
        --enable-static=no && \
    make -j$(nproc) && \
    make install

# ==========================================
# 阶段 3: 运行时精简镜像 (Runtime)
# ==========================================
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# 安装运行时基础动态库与系统工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libevent-2.1-7 \
    libssl3 \
    zlib1g \
    libsystemd0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system debian-tor \
    && useradd --system --no-create-home --gid debian-tor debian-tor

# 1. 复制 Tor 编译产物
COPY --from=c-builder /usr/local/bin/tor /usr/local/bin/tor
COPY --from=c-builder /usr/local/bin/tor-resolve /usr/local/bin/tor-resolve
COPY --from=c-builder /usr/local/bin/torify /usr/local/bin/torify
COPY --from=c-builder /usr/local/etc/tor /usr/local/etc/tor

# 2. 复制 Torsocks 编译产物
COPY --from=c-builder /usr/local/bin/torsocks /usr/local/bin/torsocks
COPY --from=c-builder /usr/local/lib/torsocks /usr/local/lib/torsocks
COPY --from=c-builder /usr/local/etc/tor/torsocks.conf /usr/local/etc/tor/torsocks.conf

# 3. 复制 Go 语言编译的混淆插件 (Snowflake + Webtunnel + Lyrebird)
COPY --from=go-builder /usr/src/snowflake/client/snowflake-client /usr/local/bin/snowflake-client
COPY --from=go-builder /usr/src/webtunnel/main/client/webtunnel-client /usr/local/bin/webtunnel-client
COPY --from=go-builder /usr/src/lyrebird/lyrebird /usr/local/bin/lyrebird

# 暴露端口 (SOCKS: 9050, Control: 9051)
EXPOSE 9050 9051

USER debian-tor

CMD ["tor"]
