#!/usr/bin/env bash
# ==============================================================================
# Hysteria 2 Manager 一键安装 / 升级 / 卸载脚本
# GitHub: https://github.com/whooc/hysteria-manager
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/etc/hysteria"
SERVICE_FILE="/etc/systemd/system/hysteria-manager.service"
DEFAULT_PORT="42075"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "此脚本必须以 root 权限运行！请使用: sudo bash $0"
    fi
}

check_dependencies() {
    log_info "检查并安装基础依赖 (Python 3, PyYAML, curl)..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y --no-install-recommends python3 python3-yaml python3-pip curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 python3-pip curl
        python3 -m pip install --break-system-packages pyyaml || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 python3-pip curl
        python3 -m pip install pyyaml || true
    elif command -v apk >/dev/null 2>&1; then
        apk add python3 py3-yaml curl
    else
        log_warn "未识别的包管理器，请确保已安装 python3 及 pyyaml"
    fi
}

install_manager() {
    check_root
    check_dependencies

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}/templates"

    # 获取当前脚本所在目录
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "${SCRIPT_DIR}/hysteria_manager.py" ]]; then
        log_info "从本地源码安装..."
        cp -f "${SCRIPT_DIR}/hysteria_manager.py" "${INSTALL_DIR}/hysteria_manager.py"
        if [[ -d "${SCRIPT_DIR}/templates" ]]; then
            cp -rf "${SCRIPT_DIR}/templates/"* "${INSTALL_DIR}/templates/" 2>/dev/null || true
        fi
    else
        log_info "从 GitHub 下载最新版本..."
        curl -fsSL "https://raw.githubusercontent.com/whooc/hysteria-manager/main/hysteria_manager.py" -o "${INSTALL_DIR}/hysteria_manager.py"
        curl -fsSL "https://raw.githubusercontent.com/whooc/hysteria-manager/main/templates/index.html" -o "${INSTALL_DIR}/templates/index.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/whooc/hysteria-manager/main/templates/login.html" -o "${INSTALL_DIR}/templates/login.html" 2>/dev/null || true
    fi

    chmod +x "${INSTALL_DIR}/hysteria_manager.py"

    # 读取或提示输入端口与密码
    PORT="${HYST_PORT:-}"
    if [[ -z "$PORT" ]]; then
        read -r -p "请输入管理面板监听端口 (默认: ${DEFAULT_PORT}): " input_port
        PORT="${input_port:-$DEFAULT_PORT}"
    fi

    PASSWORD="${HYST_PASSWORD:-}"
    if [[ -z "$PASSWORD" ]]; then
        read -r -p "请输入管理员登录密码 (留空将随机生成 12 位密码): " input_pwd
        if [[ -z "$input_pwd" ]]; then
            PASSWORD=$(tr -dc 'A-Za-z0-9!@#%^&*' </dev/urandom | head -c 12 || echo "admin_$(date +%s)")
        else
            PASSWORD="$input_pwd"
        fi
    fi

    log_info "写入 systemd 服务单元..."
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Hysteria 2 Manager Web Panel
After=network.target hysteria-server.service
Wants=hysteria-server.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="HYST_MANAGER_PORT=${PORT}"
Environment="HYST_MANAGER_PASSWORD=${PASSWORD}"
Environment="HYST_CONFIG_PATH=/etc/hysteria/config.yaml"
Environment="HYST_SERVICE_NAME=hysteria-server"
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/hysteria_manager.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria-manager
    systemctl restart hysteria-manager

    # 获取外网 IP
    PUBLIC_IP=$(curl -s4m 3 https://api.ipify.org || curl -s4m 3 https://ifconfig.me || echo "你的服务器公网IP")

    echo ""
    log_ok "=========================================================="
    log_ok "  🎉 Hysteria 2 Manager 安装部署完成！"
    log_ok "=========================================================="
    echo -e "  🌐 面板访问地址: ${GREEN}http://${PUBLIC_IP}:${PORT}${NC}"
    echo -e "  🔑 管理员密码  : ${YELLOW}${PASSWORD}${NC}"
    echo -e "  📁 配置文件路径: ${INSTALL_DIR}/hysteria_manager.py"
    echo -e "  ⚙️ 系统服务名称: hysteria-manager"
    echo ""
    echo -e "  日常管理命令:"
    echo -e "    查看状态: systemctl status hysteria-manager"
    echo -e "    查看日志: journalctl -u hysteria-manager -f"
    echo -e "    重启面板: systemctl restart hysteria-manager"
    echo -e "    停止面板: systemctl stop hysteria-manager"
    log_ok "=========================================================="
    echo ""
}

uninstall_manager() {
    check_root
    log_warn "即将卸载 Hysteria 2 Manager..."
    systemctl stop hysteria-manager 2>/dev/null || true
    systemctl disable hysteria-manager 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload

    rm -f "${INSTALL_DIR}/hysteria_manager.py"
    rm -rf "${INSTALL_DIR}/templates"
    log_ok "卸载完成！(原 /etc/hysteria/config.yaml 核心节点配置已保留)"
}

case "$1" in
    uninstall)
        uninstall_manager
        ;;
    *)
        install_manager
        ;;
esac
