# 使用 Debian 13 (Trixie) 官方精简镜像
FROM debian:trixie-slim

# 避免 apt 安装过程中的交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 安装 Tor 及基础证书，清理 apt 缓存以精简体积
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tor \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 暴露 Tor 服务的默认端口 (SOCKS: 9050, Control: 9051)
EXPOSE 9050 9051

# 切换为系统内置的低权限 debian-tor 用户运行，保证容器安全性
USER debian-tor

# 启动 Tor 服务
CMD ["tor"]
