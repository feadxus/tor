# ==========================================
# 阶段 1: 编译构建阶段 (Builder)
# ==========================================
FROM debian:trixie-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装编译所需的工具链与依赖开发库
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

# 2. 克隆 Tor 源码并切换指定版本
RUN git clone https://gitlab.torproject.org/tpo/core/tor.git && \
    cd tor && \
    git checkout tor-0.4.9.11

WORKDIR /usr/src/tor

# 3. 生成配置脚本
RUN ./autogen.sh

# 4. 执行 configure（显式添加 --disable-asciidoc 和 --disable-manpage 跳过手册编译）
RUN ./configure \
    --prefix=/usr/local \
    --disable-silent-rules \
    --disable-system-torrc \
    --disable-asciidoc \
    --disable-manpage \
    --with-tor-user=debian-tor \
    --with-tor-group=debian-tor \
    --enable-systemd

# 5. 执行全速编译与安装
RUN make -j$(nproc) && make install

# ==========================================
# 阶段 2: 运行时精简镜像 (Runtime)
# ==========================================
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装 Tor 运行所需的通用运行库
# 2. 创建 debian-tor 用户
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libevent-2.1-7 \
    libssl3 \
    zlib1g \
    libsystemd0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system debian-tor \
    && useradd --system --no-create-home --gid debian-tor debian-tor

# 3. 从 builder 阶段复制编译产物
COPY --from=builder /usr/local/bin/tor /usr/local/bin/tor
COPY --from=builder /usr/local/bin/tor-resolve /usr/local/bin/tor-resolve
COPY --from=builder /usr/local/bin/torify /usr/local/bin/torify
COPY --from=builder /usr/local/etc/tor /usr/local/etc/tor

# 4. 暴露端口并切换低权限用户运行
EXPOSE 9050 9051

USER debian-tor

CMD ["tor"]
