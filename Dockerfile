
# 使用 Debian 13 (Trixie) 作为基础镜像
FROM debian:trixie-slim

# 避免 apt 安装过程中的交互提示
ENV DEBIAN_FRONTEND=noninteractive

# 安装 Tor 及依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tor \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 暴露 Tor 默认端口（SOCKS 代理: 9050, 控制端口: 9051）
EXPOSE 9050 9051

# 切换到 Tor 内置低权限用户
USER debian-tor

# 启动 Tor 服务
CMD ["tor"]
