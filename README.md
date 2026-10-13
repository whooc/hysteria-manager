# Hysteria 2 Manager

<p align="center">
  <strong>轻量、优雅、功能完备的 Hysteria 2 可视化管理面板</strong>
  <br />
  Web GUI · 实时监控 · YAML 双向编辑 · 自动备份 · WARP 联动 · 深浅色主题
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Hysteria-2.x-6366F1?style=flat-square" alt="Hysteria 2" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome" />
</p>

---

## 🌟 核心特性

- ⚡ **极致轻量，单文件自包含**：基于 Python 纯原生标准库 + PyYAML 构建，无大型框架负担，单个脚本即可独立运行，极度节省服务器内存（占用通常 < 25MB）。
- 🌐 **全栈 IPv4 / IPv6 监听**：原生支持 `[::]` 双栈监听，纯 IPv6 机器或双栈环境均能顺畅访问。
- 📊 **实时系统与服务监控**：
  - CPU、内存、系统盘实时用量与百分比
  - 网络上行 / 下行实时速率监控与流量统计
  - Hysteria 2 服务运行状态与持续运行时长
  - 活跃 TCP/UDP 网络连接数统计
- 🛠️ **双模配置管理（GUI 表单 + 原始 YAML）**：
  - **可视化表单**：直观配置监听端口、TLS 证书/私钥/SNI、认证密码/用户名、带宽速率限制、Masquerade 伪装、ACL 规则等。
  - **原始 YAML 在线编辑**：内置语法高亮与保存前语法强校验，防止手误导致服务启动失败。
  - **安全备份机制**：每次保存自动生成带时间戳的 `.bak` 备份，支持一键重启应用新配置。
- 🚀 **节点配置与客户端导出**：
  - 自动根据当前服务配置生成客户端连接配置
  - 一键复制标准 Hysteria 2 节点链接（`hysteria2://...`）
  - 一键导出支持 **Clash Meta / Mihomo** 及 **Sing-box** 的客户端配置片段。
- 🛡️ **Cloudflare WARP 出口联动管理**：
  - 内置 WARP 出口连通性检测与 IP 归属地追踪
  - 支持一键注册新 WARP 账号并获取独立 IPv4 / IPv6 出口
  - 支持在面板中一键切换 Hysteria 2 全局走 WARP 出口或分流规则。
- 📜 **实时日志查看**：优先集成 `journalctl` 读取服务系统日志，自动降级回退到本地日志文件。
- 🎨 **自适应现代 UI**：精美的磨砂毛玻璃视觉设计，支持**深色模式**、**浅色模式**与**跟随系统**一键切换。
- 🔒 **生产级安全防护**：
  - HMAC-SHA256 签名会话 Token
  - 防暴力破解机制（连续失败 5 次自动锁定 IP 60 秒）
  - 全套安全响应头（X-Frame-Options, X-Content-Type-Options, Referrer-Policy 等）

---

## 🚀 快速开始

### 方式一：一键脚本安装（推荐）

在服务器上运行以下命令即可全自动安装、配置并注册为 systemd 开机自启服务：

```bash
curl -fsSL https://raw.githubusercontent.com/whooc/hysteria-manager/main/install.sh | sudo bash
```

> 脚本会引导设置管理面板的**监听端口**（默认 `42075`）和**管理密码**。

---

### 方式二：手动部署

#### 1. 安装基础依赖

在 Debian / Ubuntu 上：
```bash
sudo apt update
sudo apt install -y python3 python3-yaml curl
```

在 CentOS / RHEL / AlmaLinux 上：
```bash
sudo yum install -y python3 python3-pip curl
sudo pip3 install pyyaml
```

#### 2. 下载核心程序

```bash
sudo mkdir -p /etc/hysteria
sudo curl -fsSL https://raw.githubusercontent.com/whooc/hysteria-manager/main/hysteria_manager.py -o /etc/hysteria/hysteria_manager.py
sudo chmod +x /etc/hysteria/hysteria_manager.py
```

#### 3. 配置 systemd 系统服务

创建 `/etc/systemd/system/hysteria-manager.service` 文件：

```ini
[Unit]
Description=Hysteria 2 Manager Web Panel
After=network.target hysteria-server.service
Wants=hysteria-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/hysteria
Environment="HYST_MANAGER_PORT=42075"
Environment="HYST_MANAGER_PASSWORD=设置你的强密码"
Environment="HYST_CONFIG_PATH=/etc/hysteria/config.yaml"
Environment="HYST_SERVICE_NAME=hysteria-server"
ExecStart=/usr/bin/python3 /etc/hysteria/hysteria_manager.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

启动并设置开机自启：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hysteria-manager
```

查看运行状态：
```bash
sudo systemctl status hysteria-manager
```

通过浏览器访问 `http://<你的服务器IP>:42075` 即可进入管理面板。

---

## ⚙️ 环境变量说明

可通过 systemd 服务的 `Environment=` 或操作系统环境变量自定义下列参数：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `HYST_MANAGER_PORT` | `42075` | 管理面板 Web 服务监听端口（双栈 `[::]` 监听） |
| `HYST_MANAGER_PASSWORD` | `admin123` | 管理员登录密码（**生产环境强烈建议修改**） |
| `HYST_CONFIG_PATH` | `/etc/hysteria/config.yaml` | Hysteria 2 服务端 YAML 配置文件绝对路径 |
| `HYST_SERVICE_NAME` | `hysteria-server` | Hysteria 2 的 systemd 服务单元名称 |
| `HYST_LOG_FILE` | `/var/log/hysteria/server.log` | Hysteria 2 本地日志文件路径（作为回退源） |
| `HYST_SERVER_HOST` | *(空，自动识别)* | 导出客户端节点时使用的公网 IP 或域名 |

---

## 📂 目录结构

```text
hysteria-manager/
├── hysteria_manager.py        # 面板核心后端程序（含内置自包含前端）
├── hysteria-manager.service   # systemd 服务模板
├── install.sh                 # 一键快速安装与卸载脚本
├── requirements.txt           # Python 依赖清单 (PyYAML)
├── templates/                 # 外部前端模板（可选，用于定制化二次开发）
│   ├── index.html             # 主控制台前端界面
│   └── login.html             # 登录认证界面
├── LICENSE                    # MIT 开源许可证
└── README.md                  # 项目说明文档
```

> **提示**：`hysteria_manager.py` 内部已内嵌完整 Base64 模板。将单文件部署到任何服务器即可直接运行；若同级目录或 `/etc/hysteria/templates/` 存在自定义 `index.html`，程序将自动优先加载外部模板，二次开发极度方便。

---

## 🔧 日常运维命令

```bash
# 查看面板运行状态
systemctl status hysteria-manager

# 查看面板实时日志
journalctl -u hysteria-manager -f

# 重启面板服务
systemctl restart hysteria-manager

# 停止面板服务
systemctl stop hysteria-manager

# 卸载面板服务
bash install.sh uninstall
```

---

## 🛡️ 安全建议

1. **修改默认密码**：面板默认初始密码为 `admin123`，请务必在启动服务前通过 `HYST_MANAGER_PASSWORD` 环境变量设置为强密码。
2. **防火墙配置**：若使用云服务器（如阿里云、腾讯云、AWS 等），请确保在安全组中放行管理端口（默认 TCP `42075`）以及 Hysteria 2 的 UDP 端口。
3. **反向代理与 HTTPS**：如需更高安全性，可使用 Nginx / Caddy 为管理面板配置域名并开启 HTTPS 访问。

---

## 🤝 贡献与支持

欢迎提交 Issue 和 Pull Request 来帮助改进项目！如果你觉得这个项目对你有帮助，欢迎点一颗 ⭐️ **Star**！

---

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源发布。
