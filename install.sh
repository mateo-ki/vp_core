#!/usr/bin/env bash
# ==============================================================================
# VP_Core 一键安装、开服与节点生成脚本
#
# 用法:
#   bash install.sh [gen-server 参数...]
#
# 示例:
#   # 1. 默认全自动一键开服（自动探测公网 IP）
#   bash install.sh
#
#   # 2. 绑定域名（支持 Cloudflare CDN 穿透）
#   bash install.sh --domain your-domain.com
#
#   # 3. 指定协议与端口
#   bash install.sh -p hy2,ss2022 --domain your-domain.com
# ==============================================================================

set -e

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}========================================================${RESET}"
echo -e "${CYAN}${BOLD}          VP_Core 一键安装与开服向导 (install.sh)         ${RESET}"
echo -e "${CYAN}${BOLD}========================================================${RESET}\n"

# 1. 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] 错误：本脚本必须以 root 权限运行，请使用 sudo 或切换 root 用户！${RESET}"
    exit 1
fi

# 2. 架构识别
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        TARGET="x86_64-unknown-linux-musl"
        ;;
    aarch64|arm64)
        TARGET="aarch64-unknown-linux-musl"
        ;;
    *)
        echo -e "${RED}[!] 暂不支持的架构: $ARCH${RESET}"
        exit 1
        ;;
esac

echo -e "[${GREEN}+${RESET}] 检测到系统架构: ${BOLD}${ARCH} (${TARGET})${RESET}"

INSTALL_DIR="/usr/local/bin"
BIN_PATH="${INSTALL_DIR}/vpcore"

# 3. 下载或更新二进制
if [ -x "$BIN_PATH" ] && "$BIN_PATH" --version >/dev/null 2>&1; then
    CURRENT_VER="$("$BIN_PATH" --version)"
    echo -e "[${GREEN}✓${RESET}] 系统已安装 vpcore: ${BOLD}${CURRENT_VER}${RESET}"
else
    echo -e "[${CYAN}*${RESET}] 正在下载最新版 VP_Core (${TARGET})..."
    DOWNLOAD_URL="${VPCORE_DOWNLOAD_URL:-https://github.com/mateo-ki/vp_core/releases/latest/download/vpcore-${TARGET}.tar.gz}"
    TMP_DIR="$(mktemp -d)"
    
    # 尝试下载
    if curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/vpcore.tar.gz" 2>/dev/null; then
        tar -xzf "${TMP_DIR}/vpcore.tar.gz" -C "$TMP_DIR"
        mv "${TMP_DIR}/vpcore" "$BIN_PATH"
        chmod +x "$BIN_PATH"
        rm -rf "$TMP_DIR"
    elif [ -f "./vpcore" ]; then
        echo -e "[${YELLOW}!${RESET}] 未配置下载源，使用当前目录二进制进行安装..."
        cp "./vpcore" "$BIN_PATH"
        chmod +x "$BIN_PATH"
    else
        echo -e "${RED}[!] 下载失败，且本地无现成二进制。可通过环境变量 VPCORE_DOWNLOAD_URL 指定下载地址。${RESET}"
        exit 1
    fi
fi

chmod +x "$BIN_PATH"
echo -e "[${GREEN}✓${RESET}] 二进制就绪: ${BOLD}${BIN_PATH}${RESET} ($("$BIN_PATH" --version))\n"

# 4. 配置 systemd 守护服务
SERVICE_FILE="/etc/systemd/system/vpcore.service"
cat << EOF > "$SERVICE_FILE"
[Unit]
Description=VP_Core High-Performance Proxy & VPN Kernel
Documentation=https://github.com/mateo-ki/vp_core
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/vpcore
ExecStart=${BIN_PATH} run -c /etc/vpcore/config.yaml
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpcore.service >/dev/null 2>&1 || true
echo -e "[${GREEN}✓${RESET}] systemd 服务守护进程已就绪: ${BOLD}${SERVICE_FILE}${RESET}"

# 5. 执行一键生成开服配置 (将所有外部命令行参数透传给 gen-server)
echo -e "[${CYAN}*${RESET}] 正在执行节点生成..."
"$BIN_PATH" gen-server "$@"

# 6. 重启服务
echo -e "[${CYAN}*${RESET}] 正在启动 vpcore 服务..."
systemctl restart vpcore.service
sleep 1

if systemctl is-active --quiet vpcore.service; then
    echo -e "${GREEN}${BOLD}[✓] VP_Core 服务已成功启动并在后台长期守护运行！${RESET}\n"
else
    echo -e "${YELLOW}[!] 服务未能成功启动，请运行 journalctl -u vpcore -e 检查日志。${RESET}\n"
fi
