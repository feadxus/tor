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

# 3. 生成配置脚本、规范化配置并执行全速编译
# (已移除 --enable-coverage 避免生产环境性能损失，移除 sudo)
RUN ./autogen.sh && \
    ./configure \
        --prefix=/usr/local \
        --enable-expensive-hardening \
        --enable-fatal-warnings \
        --enable-pic \
        --disable-silent-rules \
        --disable-system-torrc \
        --with-tor-user=debian-tor \
        --with-tor-group=debian-tor \
        --enable-tracing-instrumentation-usdt \
        --enable-systemd && \
    make -j$(nproc) && \
    make install

# ==========================================
# 阶段 2: 运行时精简镜像 (Runtime)
# ==========================================
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# 1. 仅安装 Tor 运行所需的运行时共享动态库（不含开发头文件和编译器）
# 并创建 debian-tor 用户与组
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libevent-2.1-7t64 \
    libssl3t64 \
    zlib1g \
    libsystemd0 \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system debian-tor \
    && adduser --system --disabled-password --no-create-home --ingroup debian-tor debian-tor

# 2. 从 builder 阶段仅复制编译好的可执行程序与配置产物
COPY --from=builder /usr/local/bin/tor /usr/local/bin/tor
COPY --from=builder /usr/local/bin/tor-resolve /usr/local/bin/tor-resolve
COPY --from=builder /usr/local/bin/torify /usr/local/bin/torify
COPY --from=builder /usr/local/etc/tor /usr/local/etc/tor

# 3. 暴露端口并切换低权限用户运行
EXPOSE 9050 9051

USER debian-tor

CMD ["tor"]
