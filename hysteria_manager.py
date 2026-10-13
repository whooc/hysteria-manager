#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hysteria 2 可视化轻量管理面板（Web GUI + 实时监控 + YAML 双向编辑 + WARP 路由联动）

特性：
- 零外部前端依赖（纯单文件自包含，开箱即用）
- 双栈 IPv4 / IPv6 监听
- 仪表盘系统监控（CPU/内存/磁盘/网络速率/活跃连接数）
- YAML 可视化配置表单 与 在线原始 YAML 双向无缝编辑
- 自动备份与安全校验（保存时自动校验 YAML 语法，备份原配置）
- 节点配置与一键导出（支持 Hysteria2 格式、Clash Meta/Mihomo、Sing-box）
- Cloudflare WARP 出口联动管理（支持一键获取全新 IPv4/IPv6 出口与 ACL 分流）
- 日志实时查看（优先读取 journald，自动回退到本地日志文件）
- 深色 / 浅色 / 跟随系统主题切换
- 安全防护（HMAC-SHA256 Token 签名、登录防爆破锁定、安全响应头）
"""

import http.server
import http.client
import socketserver
import socket
import json
import subprocess
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
import base64
try:
    import yaml
except ImportError:
    yaml = None
from datetime import datetime, timezone, timedelta
import urllib.request
from urllib.parse import urlparse, parse_qs

# ---------- 配置 ----------
CONFIG_PATH = os.environ.get('HYST_CONFIG_PATH', '/etc/hysteria/config.yaml')
SERVICE_NAME = os.environ.get('HYST_SERVICE_NAME', 'hysteria-server')
LOG_FILE = os.environ.get('HYST_LOG_FILE', '/var/log/hysteria/server.log')
try:
    PORT = int(os.environ.get('HYST_MANAGER_PORT', '42075'))
except ValueError:
    PORT = 42075
PASSWORD = os.environ.get('HYST_MANAGER_PASSWORD', 'admin123')
SERVER_HOST = os.environ.get('HYST_SERVER_HOST', '').strip()

LOG_TAIL = 300            # 日志保留行数
SESSION_TTL = 86400       # 会话有效期（秒）
MAX_BODY = 4 * 1024 * 1024
LOGIN_MAX_FAIL = 5        # 连续失败上限
LOGIN_LOCK_SEC = 60       # 锁定时长

BEIJING = timezone(timedelta(hours=8))
SECRET_KEY = secrets.token_bytes(32)

SECURITY_HEADERS = (
    ('X-Content-Type-Options', 'nosniff'),
    ('X-Frame-Options', 'DENY'),
    ('Referrer-Policy', 'no-referrer'),
    ('Cache-Control', 'no-store'),
)

_prev_net = {'rx': 0, 'tx': 0, 'time': 0}
_login_state = {}
_login_lock = threading.Lock()


# ---------- 系统信息采集 ----------

def get_server_ip(handler=None):
    """获取服务器公网地址，优先顺序：环境变量 > 请求 Host > 自动探测 > 127.0.0.1"""
    if SERVER_HOST:
        return SERVER_HOST
    if handler:
        host = handler.headers.get('Host', '').partition(':')[0].strip('[]')
        if host and host not in ('127.0.0.1', 'localhost', '::1', ''):
            return host
    try:
        req = urllib.request.Request('https://api.ipify.org', headers={'User-Agent': 'curl/7.88.1'})
        with urllib.request.urlopen(req, timeout=2) as resp:
            ip = resp.read().decode('utf-8').strip()
            if ip:
                return ip
    except Exception:
        pass
    return '127.0.0.1'

def get_cpu_percent():
    try:
        with open('/proc/stat') as f:
            line = f.readline().strip().split()
        if not line or line[0] != 'cpu':
            return 0
        vals = [int(v) for v in line[1:]]
        total = sum(vals)
        idle = vals[3] + vals[4]
        time.sleep(0.1)
        with open('/proc/stat') as f:
            line2 = f.readline().strip().split()
        vals2 = [int(v) for v in line2[1:]]
        total2 = sum(vals2)
        idle2 = vals2[3] + vals2[4]
        delta_total = total2 - total
        delta_idle = idle2 - idle
        if delta_total == 0:
            return 0
        return round((1 - delta_idle / delta_total) * 100, 1)
    except Exception:
        return 0


def get_mem_info():
    try:
        with open('/proc/meminfo') as f:
            mem = {}
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    mem[parts[0].strip()] = int(parts[1].strip().split()[0])
        total = mem.get('MemTotal', 0)
        avail = mem.get('MemAvailable', 0)
        used = total - avail
        if total == 0:
            return {'total': 0, 'used': 0, 'percent': 0}
        return {
            'total': round(total / 1024),
            'used': round(used / 1024),
            'percent': round(used / total * 100, 1),
        }
    except Exception:
        return {'total': 0, 'used': 0, 'percent': 0}


def get_disk_info():
    try:
        stat = os.statvfs('/')
        total = stat.f_frsize * stat.f_blocks
        free = stat.f_frsize * stat.f_bavail
        used = total - free
        if total == 0:
            return {'total': '0B', 'used': '0B', 'percent': 0}

        def fmt(sz):
            for u in ['B', 'K', 'M', 'G', 'T']:
                if sz < 1024:
                    return '{:.1f}{}'.format(sz, u)
                sz /= 1024
            return '{:.1f}T'.format(sz)

        return {
            'total': fmt(total),
            'used': fmt(used),
            'percent': round(used / total * 100, 1),
        }
    except Exception:
        return {'total': '0B', 'used': '0B', 'percent': 0}


def get_net_info():
    empty = {'rx': '0B', 'tx': '0B', 'rx_speed': '0 B/s', 'tx_speed': '0 B/s',
             'rx_speed_raw': 0, 'tx_speed_raw': 0}
    try:
        with open('/proc/net/dev') as f:
            f.readline()
            f.readline()
            rx_total = 0
            tx_total = 0
            for line in f:
                if ':' not in line:
                    continue
                iface, data = line.split(':', 1)
                if iface.strip() == 'lo':
                    continue
                cols = data.split()
                if len(cols) >= 10:
                    rx_total += int(cols[0])
                    tx_total += int(cols[8])

        def fmt(sz):
            for u in ['B', 'K', 'M', 'G', 'T']:
                if sz < 1024:
                    return '{:.2f}{}'.format(sz, u)
                sz /= 1024
            return '{:.2f}T'.format(sz)

        def fmt_speed(bps):
            if bps < 1:
                return '0 B/s'
            for u in ['B/s', 'K/s', 'M/s', 'G/s', 'T/s']:
                if bps < 1024:
                    return '{:.1f}{}'.format(bps, u)
                bps /= 1024
            return '{:.1f}T/s'.format(bps)

        now = time.time()
        prev = _prev_net
        rx_speed = 0
        tx_speed = 0
        if prev['time'] > 0:
            elapsed = now - prev['time']
            if elapsed > 0:
                rx_speed = max(0, (rx_total - prev['rx']) / elapsed)
                tx_speed = max(0, (tx_total - prev['tx']) / elapsed)
        _prev_net['rx'] = rx_total
        _prev_net['tx'] = tx_total
        _prev_net['time'] = now

        return {
            'rx': fmt(rx_total),
            'tx': fmt(tx_total),
            'rx_speed': fmt_speed(rx_speed),
            'tx_speed': fmt_speed(tx_speed),
            'rx_speed_raw': round(rx_speed, 1),
            'tx_speed_raw': round(tx_speed, 1),
        }
    except Exception:
        return empty


def service_is_active():
    try:
        return subprocess.run(
            ['systemctl', 'is-active', SERVICE_NAME],
            capture_output=True, text=True, timeout=8
        ).returncode == 0
    except Exception:
        return False


def _main_pid():
    try:
        pid = subprocess.run(
            ['systemctl', 'show', SERVICE_NAME, '-p', 'MainPID', '--value'],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        return pid if pid and pid != '0' else None
    except Exception:
        return None


def get_conn_count():
    try:
        pid = _main_pid()
        if not pid:
            return {'tcp': 0, 'udp': 0}
        pat = re.compile(r'pid=' + re.escape(pid) + r'[,)]')
        tcp_out = subprocess.run(['ss', '-t', '-n', '-p'],
                                 capture_output=True, text=True, timeout=8)
        tcp_count = sum(1 for line in tcp_out.stdout.splitlines()
                        if line.startswith('ESTAB') and pat.search(line))
        udp_out = subprocess.run(['ss', '-u', '-a', '-n', '-p'],
                                 capture_output=True, text=True, timeout=8)
        udp_count = sum(1 for line in udp_out.stdout.splitlines() if pat.search(line))
        return {'tcp': tcp_count, 'udp': udp_count}
    except Exception:
        return {'tcp': 0, 'udp': 0}


def get_hysteria2_start_time():
    try:
        raw = subprocess.run(
            ['systemctl', 'show', SERVICE_NAME, '-p', 'ActiveEnterTimestamp',
             '--value', '--timestamp=unix'],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        if not raw:
            return 'N/A'
        ts = raw.lstrip('@').strip()
        if ts.isdigit():
            return datetime.fromtimestamp(int(ts), BEIJING).strftime('%Y-%m-%d %H:%M:%S')
        m = re.search(r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})', raw)
        return (m.group(1) + ' ' + m.group(2)) if m else raw
    except Exception:
        return 'N/A'


def read_logs():
    if os.path.exists(LOG_FILE):
        try:
            size = os.path.getsize(LOG_FILE)
            with open(LOG_FILE, 'rb') as f:
                if size > 65536:
                    f.seek(-65536, os.SEEK_END)
                    f.readline()
                data = f.read().decode('utf-8', 'replace')
            lines = [l for l in data.rstrip('\n').splitlines() if l.strip()]
            if lines:
                return lines[-LOG_TAIL:], 'file'
        except Exception:
            pass

    try:
        r = subprocess.run(
            ['journalctl', '-u', SERVICE_NAME, '-n', str(LOG_TAIL),
             '--no-pager', '-o', 'cat'],
            capture_output=True, text=True, timeout=12
        )
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        if lines:
            return lines, 'journald'
        return ['（journal 中暂无该服务的日志输出）'], 'journald'
    except Exception as e:
        return ['读取日志失败: {}'.format(e)], 'error'


# ---------- 流量统计（hysteria2 trafficStats API）----------
STATS_INTERVAL = 2.0
TARGET_LIMIT = 1000

_stats_lock = threading.Lock()
_live_streams = []
_target_stats = {}
_stream_prev = {}
_stats_seen_at = 0.0
_stats_error = ''
_stats_started = False


def _read_stats_config():
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception:
        return None, None
    m = re.search(r'(?ms)^trafficStats:\s*\n((?:[ \t]+.*\n?)*)', text)
    if not m:
        return None, None
    block = m.group(1)
    lm = re.search(r'(?m)^\s*listen:\s*(\S+)', block)
    sm = re.search(r'(?m)^\s*secret:\s*(\S+)', block)
    return (lm.group(1).strip('"\'') if lm else None,
            sm.group(1).strip('"\'') if sm else None)


def _fetch_streams():
    listen, secret = _read_stats_config()
    if not listen:
        raise RuntimeError('配置里没有 trafficStats 段')
    host, _, port = listen.rpartition(':')
    host = host.strip('[]') or '127.0.0.1'
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        conn.request('GET', '/dump/streams', headers={'Authorization': secret or ''})
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError('trafficStats 返回 HTTP {}'.format(resp.status))
        return json.loads(body.decode('utf-8')).get('streams') or []
    finally:
        conn.close()


def _iso_to_ts(s):
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return 0.0


def _stats_sampler():
    global _live_streams, _stats_seen_at, _stats_error
    while True:
        try:
            streams = _fetch_streams()
            now = time.time()
            with _stats_lock:
                for s in streams:
                    key = (s.get('connection'), s.get('stream'))
                    tx = int(s.get('tx') or 0)
                    rx = int(s.get('rx') or 0)
                    prev = _stream_prev.get(key)
                    dtx = tx if prev is None else max(0, tx - prev[0])
                    drx = rx if prev is None else max(0, rx - prev[1])
                    _stream_prev[key] = (tx, rx)

                    target = s.get('hooked_req_addr') or s.get('req_addr') or '(unknown)'
                    t = _target_stats.get(target)
                    if t is None:
                        t = {'tx': 0, 'rx': 0, 'streams': 0, 'first': now, 'last': now}
                        _target_stats[target] = t
                    t['tx'] += dtx
                    t['rx'] += drx
                    if prev is None:
                        t['streams'] += 1
                    t['last'] = now

                alive = set((s.get('connection'), s.get('stream')) for s in streams)
                for k in list(_stream_prev.keys()):
                    if k not in alive:
                        del _stream_prev[k]

                _live_streams = streams
                _stats_seen_at = now
                _stats_error = ''

                if len(_target_stats) > TARGET_LIMIT:
                    old = sorted(_target_stats.items(), key=lambda kv: kv[1]['last'])
                    for k, _v in old[:len(_target_stats) - TARGET_LIMIT]:
                        _target_stats.pop(k, None)
        except Exception as e:
            with _stats_lock:
                _stats_error = str(e)
        time.sleep(STATS_INTERVAL)


def start_stats_sampler():
    global _stats_started
    if _stats_started:
        return
    _stats_started = True
    threading.Thread(target=_stats_sampler, name='stats-sampler', daemon=True).start()


def streams_snapshot(top=200):
    now = time.time()
    with _stats_lock:
        live = []
        for s in _live_streams:
            init = _iso_to_ts(s.get('initial_at') or '')
            last = _iso_to_ts(s.get('last_active_at') or '')
            live.append({
                'target': s.get('hooked_req_addr') or s.get('req_addr') or '(unknown)',
                'req_addr': s.get('req_addr') or '',
                'hooked': s.get('hooked_req_addr') or '',
                'state': s.get('state') or '',
                'tx': int(s.get('tx') or 0),
                'rx': int(s.get('rx') or 0),
                'lifetime': round(last - init, 1) if (init and last) else 0,
                'idle': round(now - last, 1) if last else 0,
            })
        live.sort(key=lambda x: x['tx'] + x['rx'], reverse=True)

        targets = [{
            'target': k,
            'tx': v['tx'],
            'rx': v['rx'],
            'streams': v['streams'],
            'idle': round(now - v['last'], 1),
        } for k, v in _target_stats.items()]
        targets.sort(key=lambda x: x['tx'] + x['rx'], reverse=True)

        return {
            'live': live[:top],
            'targets': targets[:top],
            'live_count': len(live),
            'target_count': len(targets),
            'seen_at': _stats_seen_at,
            'error': _stats_error,
        }


# ---------- 配置解析与生成 ----------
def parse_yaml_config(content):
    if yaml is None:
        return None, '缺少依赖 PyYAML，请先运行: pip install pyyaml 或 apt install python3-yaml'
    try:
        data = yaml.safe_load(content) or {}
    except Exception as e:
        return None, str(e)
    
    cfg = {}
    cfg['listen'] = str(data.get('listen', ':51235'))
    
    tls = data.get('tls', {}) or {}
    cfg['tls'] = {
        'cert': str(tls.get('cert', '/etc/hysteria/cert.crt')),
        'key': str(tls.get('key', '/etc/hysteria/private.key')),
        'sni': str(tls.get('sni', '')) if tls.get('sni') else ''
    }
    
    auth = data.get('auth', {}) or {}
    cfg['auth'] = {
        'type': str(auth.get('type', 'password')),
        'password': str(auth.get('password', ''))
    }
    
    masq = data.get('masquerade', {}) or {}
    mtype = masq.get('type', 'proxy')
    p = masq.get('proxy', {}) if isinstance(masq.get('proxy'), dict) else {}
    cfg['masquerade'] = {
        'type': mtype,
        'proxy': {
            'url': str(p.get('url', 'https://maimai.sega.jp')),
            'rewriteHost': bool(p.get('rewriteHost', True))
        }
    }
    
    quic = data.get('quic', {}) or {}
    cfg['quic'] = {
        'initStreamReceiveWindow': int(quic.get('initStreamReceiveWindow', 16777216)),
        'maxStreamReceiveWindow': int(quic.get('maxStreamReceiveWindow', 16777216)),
        'initConnReceiveWindow': int(quic.get('initConnReceiveWindow', 33554432)),
        'maxConnReceiveWindow': int(quic.get('maxConnReceiveWindow', 33554432))
    }
    
    bandwidth = data.get('bandwidth', {}) or {}
    cfg['bandwidth'] = {
        'up': str(bandwidth.get('up', '')) if bandwidth.get('up') else '',
        'down': str(bandwidth.get('down', '')) if bandwidth.get('down') else ''
    }
    cfg['ignoreClientBandwidth'] = bool(data.get('ignoreClientBandwidth', False))
    
    traffic = data.get('trafficStats', {}) or {}
    cfg['trafficStats'] = {
        'listen': str(traffic.get('listen', '127.0.0.1:19999')),
        'secret': str(traffic.get('secret', ''))
    }
    
    outbounds_raw = data.get('outbounds', []) or []
    outbounds = []
    for ob in outbounds_raw:
        if not isinstance(ob, dict):
            continue
        item = {
            'name': str(ob.get('name', '')),
            'type': str(ob.get('type', 'socks5'))
        }
        if item['type'] == 'socks5':
            s5 = ob.get('socks5', {}) or {}
            item['socks5'] = {
                'addr': str(s5.get('addr', '')),
                'username': str(s5.get('username', '')),
                'password': str(s5.get('password', ''))
            }
        elif item['type'] == 'direct':
            d = ob.get('direct', {}) or {}
            item['direct'] = {
                'mode': d.get('mode', 4)
            }
        elif item['type'] == 'http':
            h = ob.get('http', {}) or {}
            item['http'] = {
                'addr': str(h.get('addr', '')),
                'username': str(h.get('username', '')),
                'password': str(h.get('password', ''))
            }
        outbounds.append(item)
    cfg['outbounds'] = outbounds
    
    acl_raw = data.get('acl', {}) or {}
    inline = acl_raw.get('inline', []) or []
    acl_rules = []
    for line in inline:
        line_str = str(line).strip()
        if not line_str:
            continue
        if '(' in line_str and line_str.endswith(')'):
            idx = line_str.index('(')
            outbound = line_str[:idx].strip()
            rule = line_str[idx+1:-1].strip()
            acl_rules.append({'outbound': outbound, 'rule': rule, 'raw': line_str})
        else:
            acl_rules.append({'outbound': '', 'rule': line_str, 'raw': line_str})
    cfg['acl'] = {'rules': acl_rules}
    
    return cfg, None


def generate_yaml(cfg):
    lines = []
    lines.append("# =========================================")
    lines.append("# Access Control List (ACL)")
    lines.append("# =========================================")
    lines.append("acl:")
    lines.append("  inline:")
    rules = cfg.get('acl', {}).get('rules', [])
    if rules:
        for r in rules:
            ob = str(r.get('outbound', '')).strip()
            rule = str(r.get('rule', '')).strip()
            if ob and rule:
                lines.append(f"    - {ob}({rule})")
            elif rule:
                lines.append(f"    - {rule}")
    else:
        lines.append("    - direct_v4(0.0.0.0/0)")
        lines.append("    - direct_v6(::/0)")
    lines.append("")
    
    lines.append("# =========================================")
    lines.append("# Outbounds")
    lines.append("# =========================================")
    lines.append("outbounds:")
    for ob in cfg.get('outbounds', []):
        lines.append(f"  - name: {ob.get('name')}")
        lines.append(f"    type: {ob.get('type')}")
        ob_type = ob.get('type')
        if ob_type == 'socks5':
            s5 = ob.get('socks5', {}) or {}
            lines.append("    socks5:")
            lines.append(f"      addr: {s5.get('addr', '')}")
            if s5.get('username'):
                lines.append(f"      username: {s5.get('username')}")
            if s5.get('password'):
                lines.append(f"      password: {s5.get('password')}")
        elif ob_type == 'direct':
            d = ob.get('direct', {}) or {}
            lines.append("    direct:")
            lines.append(f"      mode: {d.get('mode', 4)}")
        elif ob_type == 'http':
            h = ob.get('http', {}) or {}
            lines.append("    http:")
            lines.append(f"      addr: {h.get('addr', '')}")
            if h.get('username'):
                lines.append(f"      username: {h.get('username')}")
            if h.get('password'):
                lines.append(f"      password: {h.get('password')}")
        lines.append("")
        
    lines.append("# =========================================")
    lines.append("# Server & Core Settings")
    lines.append("# =========================================")
    listen = str(cfg.get('listen', ':51235')).strip()
    if not listen.startswith(':') and not re.match(r'^\d', listen) and not listen.startswith('['):
        listen = ':' + listen
    lines.append(f"listen: {listen}")
    lines.append("")
    
    tls = cfg.get('tls', {}) or {}
    lines.append("tls:")
    lines.append(f"  cert: {tls.get('cert', '/etc/hysteria/cert.crt')}")
    lines.append(f"  key: {tls.get('key', '/etc/hysteria/private.key')}")
    if tls.get('sni'):
        lines.append(f"  sni: {tls.get('sni')}")
    lines.append("")
    
    auth = cfg.get('auth', {}) or {}
    lines.append("auth:")
    lines.append(f"  type: {auth.get('type', 'password')}")
    lines.append(f"  password: {auth.get('password', '')}")
    lines.append("")
    
    masq = cfg.get('masquerade', {}) or {}
    lines.append("masquerade:")
    lines.append(f"  type: {masq.get('type', 'proxy')}")
    if masq.get('type') == 'proxy':
        lines.append("  proxy:")
        p = masq.get('proxy', {}) or {}
        lines.append(f"    url: {p.get('url', 'https://maimai.sega.jp')}")
        lines.append(f"    rewriteHost: {'true' if p.get('rewriteHost', True) else 'false'}")
    lines.append("")
    
    quic = cfg.get('quic', {}) or {}
    lines.append("quic:")
    lines.append(f"  initStreamReceiveWindow: {int(quic.get('initStreamReceiveWindow', 16777216))}")
    lines.append(f"  maxStreamReceiveWindow: {int(quic.get('maxStreamReceiveWindow', 16777216))}")
    lines.append(f"  initConnReceiveWindow: {int(quic.get('initConnReceiveWindow', 33554432))}")
    lines.append(f"  maxConnReceiveWindow: {int(quic.get('maxConnReceiveWindow', 33554432))}")
    lines.append("")
    
    bw = cfg.get('bandwidth', {}) or {}
    if bw.get('up') or bw.get('down'):
        lines.append("bandwidth:")
        if bw.get('up'):
            lines.append(f"  up: {bw.get('up')}")
        if bw.get('down'):
            lines.append(f"  down: {bw.get('down')}")
        lines.append("")
    if cfg.get('ignoreClientBandwidth'):
        lines.append("ignoreClientBandwidth: true")
        lines.append("")
        
    ts = cfg.get('trafficStats', {}) or {}
    if ts.get('listen'):
        lines.append("# Traffic Stats API")
        lines.append("trafficStats:")
        lines.append(f"  listen: {ts.get('listen', '127.0.0.1:19999')}")
        if ts.get('secret'):
            lines.append(f"  secret: {ts.get('secret')}")
        lines.append("")
        
    return "\n".join(lines)



# ---------- 出站测试与 WARP 工具箱核心逻辑 ----------
def test_outbound_curl(ob):
    if not isinstance(ob, dict):
        return {'success': False, 'error': '无效的节点数据'}
    ob_type = ob.get('type')
    cmd = ['curl', '-s', '-m', '6', '-w', '\nTIME=%{time_total}']
    
    if ob_type == 'socks5':
        s5 = ob.get('socks5', {}) or {}
        addr = str(s5.get('addr', '')).strip()
        user = str(s5.get('username', '')).strip()
        pwd = str(s5.get('password', '')).strip()
        auth = f"{user}:{pwd}@" if user or pwd else ""
        cmd += ['--socks5-hostname', f"{auth}{addr}"]
    elif ob_type == 'direct':
        mode = ob.get('direct', {}).get('mode', 4)
        cmd.append('-6' if str(mode) == '6' else '-4')
    elif ob_type == 'http':
        h = ob.get('http', {}) or {}
        addr = str(h.get('addr', '')).strip()
        user = str(h.get('username', '')).strip()
        pwd = str(h.get('password', '')).strip()
        auth = f"{user}:{pwd}@" if user or pwd else ""
        cmd += ['-x', f"http://{auth}{addr}"]
    else:
        return {'success': False, 'error': f'未知出站类型: {ob_type}'}
        
    cmd.append('https://cloudflare.com/cdn-cgi/trace')
    
    try:
        t0 = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        elapsed = round((time.time() - t0) * 1000)
        
        if res.returncode != 0:
            err_msg = res.stderr.strip() or f'curl 退出码 {res.returncode}'
            return {'success': False, 'error': f'连接超时或失败 ({err_msg})'}
            
        out = res.stdout
        ip_m = re.search(r'(?m)^ip=(.*)$', out)
        loc_m = re.search(r'(?m)^loc=(.*)$', out)
        colo_m = re.search(r'(?m)^colo=(.*)$', out)
        warp_m = re.search(r'(?m)^warp=(.*)$', out)
        time_m = re.search(r'(?m)^TIME=(.*)$', out)
        
        if not ip_m:
            return {'success': False, 'error': '未解析到出口 IP'}
            
        delay = elapsed
        if time_m:
            try:
                delay = round(float(time_m.group(1).strip()) * 1000)
            except Exception:
                pass
                
        return {
            'success': True,
            'ip': ip_m.group(1).strip(),
            'loc': loc_m.group(1).strip() if loc_m else '',
            'colo': colo_m.group(1).strip() if colo_m else '',
            'warp': warp_m.group(1).strip() if warp_m else 'off',
            'delay': delay
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def warp_is_active():
    try:
        r = subprocess.run(['systemctl', 'is-active', 'hysteria-warp.service'], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == 'active'
    except Exception:
        return False


def register_warp_account():
    try:
        priv_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
        pub_key = subprocess.check_output(['wg', 'pubkey'], input=priv_key.encode()).decode().strip()

        body = json.dumps({
            "key": pub_key,
            "tos": datetime.now().isoformat() + "Z"
        }).encode('utf-8')

        req = urllib.request.Request("https://api.cloudflareclient.com/v0a2158/reg", data=body,
                                     headers={"User-Agent": "okhttp/3.12.1", "Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())

        v4 = data['config']['interface']['addresses']['v4']
        v6 = data['config']['interface']['addresses']['v6']
        peer_pub = data['config']['peers'][0]['public_key']
        endpoint = "2606:4700:d0::a29f:c001"
        port = 2408

        sb_config = {
          "log": {
            "level": "warn"
          },
          "inbounds": [
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": 40000
            }
          ],
          "endpoints": [
            {
              "type": "wireguard",
              "tag": "warp-ep",
              "address": [
                f"{v4}/32",
                f"{v6}/128"
              ],
              "private_key": priv_key,
              "peers": [
                {
                  "address": endpoint,
                  "port": port,
                  "public_key": peer_pub,
                  "allowed_ips": ["0.0.0.0/0", "::/0"]
                }
              ]
            }
          ],
          "route": {
            "rules": [
              {
                "inbound": "socks-in",
                "outbound": "warp-ep"
              }
            ]
          }
        }

        os.makedirs('/etc/hysteria', exist_ok=True)
        with open('/etc/hysteria/warp.json', 'w', encoding='utf-8') as f:
            json.dump(sb_config, f, indent=2)

        subprocess.run(['systemctl', 'restart', 'hysteria-warp.service'], capture_output=True, timeout=10)
        return {'success': True, 'message': 'WARP 账号已重新注册并获取全新 IPv6 IP', 'v4': v4, 'v6': v6}
    except Exception as e:
        return {'success': False, 'error': f'注册 WARP 失败: {e}'}


def get_warp_status():
    running = warp_is_active()
    trace = {}
    if running:
        trace = test_outbound_curl({'type': 'socks5', 'socks5': {'addr': '127.0.0.1:40000'}})
    
    hy2_has_warp = False
    hy2_warp_global = False
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            raw = f.read()
        cfg, _ = parse_yaml_config(raw)
        if cfg and 'acl' in cfg:
            rules = cfg['acl'].get('rules', [])
            for r in rules:
                ob = str(r.get('outbound', '')).strip()
                rule = str(r.get('rule', '')).strip()
                if ob == 'warp':
                    hy2_has_warp = True
                    if rule in ('all', '0.0.0.0/0', '::/0'):
                        hy2_warp_global = True
    except Exception:
        pass
        
    return {
        'running': running,
        'hy2_has_warp': hy2_has_warp,
        'hy2_warp_global': hy2_warp_global,
        'trace': trace
    }


def toggle_hy2_warp_route(mode):
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            raw = f.read()
        cfg, err = parse_yaml_config(raw)
        if err or not cfg:
            return {'success': False, 'error': f'解析现有配置失败: {err}'}
            
        outbounds = cfg.setdefault('outbounds', [])
        has_warp_ob = any(isinstance(o, dict) and o.get('name') == 'warp' for o in outbounds)
        if not has_warp_ob:
            outbounds.append({
                'name': 'warp',
                'type': 'socks5',
                'socks5': {
                    'addr': '127.0.0.1:40000'
                }
            })
            
        acl = cfg.setdefault('acl', {})
        rules = acl.setdefault('rules', [])
        
        # 移除已有的所有 warp 规则
        clean_rules = [r for r in rules if r.get('outbound') != 'warp']
        
        if mode == 'global':
            # 全局走 WARP：保留 onion，将 warp(all) 放在首位
            onion_rules = [r for r in clean_rules if 'suffix:onion' in str(r.get('rule', ''))]
            rest_rules = [r for r in clean_rules if 'suffix:onion' not in str(r.get('rule', ''))]
            new_rules = onion_rules + [{'outbound': 'warp', 'rule': 'all', 'raw': 'warp(all)'}] + rest_rules
            
        elif mode == 'unlock':
            # 流媒体 / AI 解锁走 WARP
            unlock_domains = [
                'suffix:openai.com',
                'suffix:chatgpt.com',
                'suffix:oaistatic.com',
                'suffix:oaiusercontent.com',
                'suffix:anthropic.com',
                'suffix:claude.ai',
                'suffix:netflix.com',
                'suffix:netflix.net',
                'suffix:nflxvideo.net',
                'suffix:nflximg.net',
                'suffix:disneyplus.com',
                'suffix:disney-plus.net',
                'suffix:dssott.com',
                'suffix:bamgrid.com'
            ]
            warp_unlock_rules = [{'outbound': 'warp', 'rule': d, 'raw': f'warp({d})'} for d in unlock_domains]
            onion_rules = [r for r in clean_rules if 'suffix:onion' in str(r.get('rule', ''))]
            rest_rules = [r for r in clean_rules if 'suffix:onion' not in str(r.get('rule', ''))]
            new_rules = onion_rules + warp_unlock_rules + rest_rules
            
        elif mode == 'disable':
            # 恢复默认：仅清除 warp 规则
            new_rules = clean_rules
        else:
            return {'success': False, 'error': f'未知分流模式: {mode}'}
            
        acl['rules'] = new_rules
        cfg['acl'] = acl
        cfg['outbounds'] = outbounds
        
        new_yaml = generate_yaml(cfg)
        yaml.safe_load(new_yaml)
        
        backup_config()
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(new_yaml)
            
        # 重启 Hysteria 2 服务以生效
        subprocess.run(['systemctl', 'restart', SERVICE_NAME], capture_output=True, text=True, timeout=30)
        return {'success': True, 'mode': mode, 'message': 'Hysteria 2 分流配置已更新并重启'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def backup_config():
    if os.path.exists(CONFIG_PATH):
        ts = datetime.now().strftime('%Y%m%d-%H%M%S')
        bak = f"{CONFIG_PATH}.bak.{ts}"
        try:
            with open(CONFIG_PATH, 'rb') as src, open(bak, 'wb') as dst:
                dst.write(src.read())
        except Exception:
            pass


# ---------- 会话 ----------
def _sign(payload):
    return hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()


def create_token():
    data = secrets.token_hex(16)
    exp = str(int(time.time()) + SESSION_TTL)
    payload = data + '|' + exp
    return payload + '|' + _sign(payload)


def verify_token(token):
    if not token:
        return False
    parts = token.split('|')
    if len(parts) != 3:
        return False
    data, exp, sig = parts
    if not exp.isdigit() or int(exp) < time.time():
        return False
    return hmac.compare_digest(sig, _sign(data + '|' + exp))


def check_auth(handler):
    cookies = handler.headers.get('Cookie', '')
    for c in cookies.split(';'):
        c = c.strip()
        if c.startswith('session='):
            if verify_token(c.split('=', 1)[1]):
                return True
    return False


def _norm_ip(handler):
    ip = handler.client_address[0]
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    return ip


def login_lock_remaining(ip):
    with _login_lock:
        rec = _login_state.get(ip)
        if not rec:
            return 0
        cnt, until = rec
        if until > time.time():
            return int(until - time.time()) + 1
        return 0


def login_record_fail(ip):
    with _login_lock:
        now = time.time()
        cnt, until = _login_state.get(ip, (0, 0.0))
        if until and until <= now:
            cnt = 0
        cnt += 1
        if cnt >= LOGIN_MAX_FAIL:
            until = now + LOGIN_LOCK_SEC
            cnt = 0
        _login_state[ip] = (cnt, until)


def login_clear(ip):
    with _login_lock:
        _login_state.pop(ip, None)


# ---------- 登录 HTML ----------
HTML_LOGIN = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hysteria 2 - 登录</title>
<script>
(function(){
    var theme = localStorage.getItem('hy2_theme') || 'auto';
    if(theme === 'light' || (theme === 'auto' && window.matchMedia && !window.matchMedia('(prefers-color-scheme: dark)').matches)){
        document.documentElement.classList.add('theme-light');
    }
})();
</script>
<style>
:root {
  --primary: #6366f1; --primary-hover: #4f46e5;
  --bg-main: #0f172a; --bg-card: #1e293b; --bg-input: #0f172a;
  --border: #334155; --border-input: #475569;
  --text-main: #f8fafc; --text-muted: #94a3b8;
  --danger: #f87171; --danger-bg: rgba(239,68,68,0.1); --danger-border: rgba(239,68,68,0.2);
}
html.theme-light {
  --bg-main: #f1f5f9; --bg-card: #ffffff; --bg-input: #ffffff;
  --border: #e2e8f0; --border-input: #cbd5e1;
  --text-main: #0f172a; --text-muted: #64748b;
  --danger: #ef4444; --danger-bg: rgba(239,68,68,0.1); --danger-border: rgba(239,68,68,0.2);
}
* { margin:0; padding:0; box-sizing:border-box }
body { height:100vh; display:flex; align-items:center; justify-content:center; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:var(--bg-main); color:var(--text-main); transition: background 0.3s }
.login-box { background:var(--bg-card); padding:42px; border-radius:16px; box-shadow:0 10px 40px rgba(0,0,0,0.2); width:380px; text-align:center; border:1px solid var(--border); transition: background 0.3s, border 0.3s }
.login-box h1 { font-size:24px; margin-bottom:8px; color:var(--text-main); display:flex; align-items:center; justify-content:center; gap:10px }
.login-box h1 span { color:var(--primary) }
.login-box .sub { font-size:13px; color:var(--text-muted); margin-bottom:28px }
.login-box input[type=password] { width:100%; padding:13px 16px; border:1px solid var(--border-input); border-radius:8px; background:var(--bg-input); color:var(--text-main); font-size:16px; outline:none; margin-bottom:18px; transition:all .2s }
.login-box input[type=password]:focus { border-color:var(--primary); box-shadow:0 0 0 3px rgba(99,102,241,0.25) }
.login-box button { width:100%; padding:13px; border:none; border-radius:8px; background:var(--primary); color:#fff; font-size:16px; font-weight:600; cursor:pointer; transition:all .15s }
.login-box button:hover { background:var(--primary-hover) }
.error-msg { color:var(--danger); font-size:13px; margin-bottom:14px; background:var(--danger-bg); padding:8px; border-radius:6px; border:1px solid var(--danger-border); display:none }
</style>
</head>
<body>
<div class="login-box">
    <h1><span>&#9889;</span> Hysteria 2</h1>
    <div class="sub">管理面板安全认证</div>
    <div class="error-msg" id="err">__ERROR__</div>
    <form method="POST" action="/login">
        <input type="password" name="password" placeholder="请输入管理员密码" autofocus required>
        <button type="submit">登 录</button>
    </form>
</div>
<script>
(function(){
    var p = new URLSearchParams(location.search);
    if (p.has('error')) {
        var el = document.getElementById('err');
        el.style.display = 'block';
        el.textContent = p.get('error') === 'locked' ? '错误次数过多，请稍后再试' : '密码错误，请重试';
    }
})();
</script>
</body>
</html>"""


# ---------- 主管理控制台 HTML（Base64 完整还原，杜绝转义字符污染）----------
_B64_HTML_TEMPLATE = b"""PCFET0NUWVBFIGh0bWw+Cgo8aHRtbCBsYW5nPSJ6aC1DTiI+Cgo8aGVhZD4KCjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KCjxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MS4wIj4KCjx0aXRsZT5IeXN0ZXJpYSAyIOWPr+inhuWMlueuoeeQhumdouadvzwvdGl0bGU+Cgo8c3R5bGU+CgoKCgovKiBUaGVtZSBTd2l0Y2hpbmcgU3R5bGVzICovCgo6cm9vdHsKCiAgLS1wcmltYXJ5OiM2MzY2ZjE7LS1wcmltYXJ5LWhvdmVyOiM0ZjQ2ZTU7CgogIC0tYmctbWFpbjojMGYxNzJhOy0tYmctY2FyZDojMWUyOTNiOy0tYmctc3ViY2FyZDojMTExOTI3Oy0tYmctaW5wdXQ6IzBmMTcyYTsKCiAgLS1iZy1oZWFkZXI6IzE4MjIzNDstLWJnLWhlYWRlci1hbHBoYTpyZ2JhKDMwLDQxLDU5LDAuNyk7LS1iZy1ob3ZlcjpyZ2JhKDI1NSwyNTUsMjU1LDAuMDUpOy0tYnRuLWJnOiMzMzQxNTU7LS1idG4tYm9yZGVyOiM0NzU1Njk7LS1idG4tdGV4dDojY2JkNWUxOy0tYnRuLWhvdmVyOiM0NzU1Njk7LS1ib3JkZXI6IzMzNDE1NTstLWJvcmRlci1saWdodDojNDc1NTY5OwoKICAtLXRleHQtbWFpbjojZjhmYWZjOy0tdGV4dC1tdXRlZDojOTRhM2I4Oy0tdGV4dC1zdWI6I2NiZDVlMTsKCiAgLS1zdWNjZXNzOiMxMGI5ODE7LS1kYW5nZXI6I2VmNDQ0NDstLXdhcm5pbmc6I2Y1OWUwYjstLWluZm86IzM4YmRmODsKCn0KCmJvZHkudGhlbWUtbGlnaHR7CgogIC0tYmctbWFpbjojZjFmNWY5Oy0tYmctY2FyZDojZmZmZmZmOy0tYmctc3ViY2FyZDojZjhmYWZjOy0tYmctaW5wdXQ6I2ZmZmZmZjsKCiAgLS1iZy1oZWFkZXI6I2ZmZmZmZjstLWJnLWhlYWRlci1hbHBoYTpyZ2JhKDI1NSwyNTUsMjU1LDAuODUpOy0tYmctaG92ZXI6cmdiYSgwLDAsMCwwLjA1KTstLWJ0bi1iZzojZTJlOGYwOy0tYnRuLWJvcmRlcjojY2JkNWUxOy0tYnRuLXRleHQ6IzQ3NTU2OTstLWJ0bi1ob3ZlcjojY2JkNWUxOy0tYm9yZGVyOiNlMmU4ZjA7LS1ib3JkZXItbGlnaHQ6I2NiZDVlMTsKCiAgLS10ZXh0LW1haW46IzBmMTcyYTstLXRleHQtbXV0ZWQ6IzY0NzQ4YjstLXRleHQtc3ViOiMzMzQxNTU7Cgp9CgoudGhlbWUtc3dpdGNoZXJ7ZGlzcGxheTppbmxpbmUtZmxleDtnYXA6MnB4O2JhY2tncm91bmQ6dmFyKC0tYmctaW5wdXQpO3BhZGRpbmc6MnB4O2JvcmRlci1yYWRpdXM6OHB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKX0KCi50aGVtZS1idG57cGFkZGluZzo0cHggOXB4O2JvcmRlcjpub25lO2JhY2tncm91bmQ6dHJhbnNwYXJlbnQ7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NjAwO2JvcmRlci1yYWRpdXM6NnB4O2N1cnNvcjpwb2ludGVyO2Rpc3BsYXk6aW5saW5lLWZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo0cHg7dHJhbnNpdGlvbjphbGwgLjE1c30KCi50aGVtZS1idG46aG92ZXJ7Y29sb3I6dmFyKC0tdGV4dC1tYWluKX0KCi50aGVtZS1idG4uYWN0aXZle2JhY2tncm91bmQ6dmFyKC0tcHJpbWFyeSk7Y29sb3I6I2ZmZn0KCgoKLyogT3V0Ym91bmQgVGVzdCBCYWRnZSAqLwoKLm9iLXRlc3QtcmVzdWx0e21hcmdpbi10b3A6NnB4O21pbi1oZWlnaHQ6MjRweDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyfQoKLm9iLXRlc3QtYmFkZ2V7ZGlzcGxheTppbmxpbmUtZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweDtwYWRkaW5nOjNweCA4cHg7Ym9yZGVyLXJhZGl1czo2cHg7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NjAwO2ZvbnQtZmFtaWx5Om1vbm9zcGFjZX0KCi5vYi10ZXN0LWJhZGdlLm9re2JhY2tncm91bmQ6cmdiYSgxNiwxODUsMTI5LDAuMTUpO2NvbG9yOnZhcigtLXN1Y2Nlc3MpO2JvcmRlcjoxcHggc29saWQgcmdiYSgxNiwxODUsMTI5LDAuMyl9Cgoub2ItdGVzdC1iYWRnZS5lcnJ7YmFja2dyb3VuZDpyZ2JhKDIzOSw2OCw2OCwwLjE1KTtjb2xvcjp2YXIoLS1kYW5nZXIpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyMzksNjgsNjgsMC4zKX0KCi53YXJwLXRhZ3tiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsI2Y5NzMxNiwjZWE1ODBjKTtjb2xvcjojZmZmO3BhZGRpbmc6MXB4IDVweDtib3JkZXItcmFkaXVzOjNweDtmb250LXNpemU6MTBweDtmb250LXdlaWdodDo3MDB9CgouYnRuLXRlc3Qtb2J7Y29sb3I6dmFyKC0taW5mbyk7Ym9yZGVyLWNvbG9yOnJnYmEoNTYsMTg5LDI0OCwwLjQpfQoKLmJ0bi10ZXN0LW9iOmhvdmVye2JhY2tncm91bmQ6cmdiYSg1NiwxODksMjQ4LDAuMTUpfQoKCgovKiBXQVJQIENhcmQgU3R5bGVzICovCgoud2FycC1zdGF0dXMtYm94e2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47ZmxleC13cmFwOndyYXA7Z2FwOjEycHg7cGFkZGluZzoxNHB4O2JhY2tncm91bmQ6dmFyKC0tYmctc3ViY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6OHB4fQoKLndhcnAtaXAtYm94e2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTtmb250LXNpemU6MTNweDtwYWRkaW5nOjEwcHggMTRweDtiYWNrZ3JvdW5kOnZhcigtLWJnLWlucHV0KTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czo2cHg7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtmbGV4LXdyYXA6d3JhcDtnYXA6OHB4fQoKCgo6cm9vdHsKCiAgLS1wcmltYXJ5OiM2MzY2ZjE7LS1wcmltYXJ5LWhvdmVyOiM0ZjQ2ZTU7CgogIC0tYmctbWFpbjojMGYxNzJhOy0tYmctY2FyZDojMWUyOTNiOy0tYmctaW5wdXQ6IzBmMTcyYTsKCiAgLS1ib3JkZXI6IzMzNDE1NTstLWJvcmRlci1saWdodDojNDc1NTY5OwoKICAtLXRleHQtbWFpbjojZjhmYWZjOy0tdGV4dC1tdXRlZDojOTRhM2I4OwoKICAtLXN1Y2Nlc3M6IzEwYjk4MTstLWRhbmdlcjojZWY0NDQ0Oy0td2FybmluZzojZjU5ZTBiOy0taW5mbzojMzhiZGY4OwoKfQoKKnttYXJnaW46MDtwYWRkaW5nOjA7Ym94LXNpemluZzpib3JkZXItYm94fQoKaHRtbCxib2R5e2hlaWdodDoxMDB2aDtvdmVyZmxvdzpoaWRkZW47Zm9udC1mYW1pbHk6LWFwcGxlLXN5c3RlbSxCbGlua01hY1N5c3RlbUZvbnQsIlNlZ29lIFVJIixSb2JvdG8sIkhlbHZldGljYSBOZXVlIixBcmlhbCxzYW5zLXNlcmlmO2JhY2tncm91bmQ6dmFyKC0tYmctbWFpbik7Y29sb3I6dmFyKC0tdGV4dC1tYWluKX0KCmJvZHl7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbn0KCgoKLyogSGVhZGVyICovCgouaGVhZGVye2JhY2tncm91bmQ6dmFyKC0tYmctY2FyZCk7cGFkZGluZzoxMHB4IDIwcHg7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtmbGV4LXdyYXA6d3JhcDtnYXA6MTBweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2ZsZXgtc2hyaW5rOjB9CgouaGVhZGVyLWxlZnR7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweH0KCi5oZWFkZXIgaDF7Zm9udC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6NzAwO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDtjb2xvcjp2YXIoLS10ZXh0LW1haW4pfQoKLmhlYWRlciBoMSBzcGFue2NvbG9yOnZhcigtLXByaW1hcnkpfQoKLmJhZGdlLXN0YXR1c3tkaXNwbGF5OmlubGluZS1mbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NnB4O3BhZGRpbmc6M3B4IDEwcHg7Ym9yZGVyLXJhZGl1czoyMHB4O2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjYwMDtiYWNrZ3JvdW5kOnJnYmEoMTYsMTg1LDEyOSwwLjEyKTtjb2xvcjp2YXIoLS1zdWNjZXNzKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMTYsMTg1LDEyOSwwLjMpfQoKLmJhZGdlLXN0YXR1cy5zdG9wcGVke2JhY2tncm91bmQ6cmdiYSgyMzksNjgsNjgsMC4xMik7Y29sb3I6dmFyKC0tZGFuZ2VyKTtib3JkZXItY29sb3I6cmdiYSgyMzksNjgsNjgsMC4zKX0KCi5kb3QtcHVsc2V7d2lkdGg6OHB4O2hlaWdodDo4cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDpjdXJyZW50Q29sb3I7ZGlzcGxheTppbmxpbmUtYmxvY2s7YW5pbWF0aW9uOnB1bHNlIDJzIGluZmluaXRlfQoKQGtleWZyYW1lcyBwdWxzZXswJXtvcGFjaXR5OjE7dHJhbnNmb3JtOnNjYWxlKDEpfTUwJXtvcGFjaXR5OjAuNDt0cmFuc2Zvcm06c2NhbGUoMC44NSl9MTAwJXtvcGFjaXR5OjE7dHJhbnNmb3JtOnNjYWxlKDEpfX0KCgoKLnJpZ2h0LWJhcntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7ZmxleC13cmFwOndyYXB9CgouY29udHJvbHN7ZGlzcGxheTpmbGV4O2dhcDo2cHh9CgouYnRue3BhZGRpbmc6N3B4IDE0cHg7Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czo2cHg7Y3Vyc29yOnBvaW50ZXI7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NjAwO2Rpc3BsYXk6aW5saW5lLWZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo2cHg7dHJhbnNpdGlvbjphbGwgLjE1c30KCi5idG46aG92ZXJ7ZmlsdGVyOmJyaWdodG5lc3MoMS4xNSk7dHJhbnNmb3JtOnRyYW5zbGF0ZVkoLTFweCl9CgouYnRuOmFjdGl2ZXt0cmFuc2Zvcm06dHJhbnNsYXRlWSgwKX0KCi5idG4tc3RhcnR7YmFja2dyb3VuZDojMTU4MDNkO2NvbG9yOiNmZmZ9CgouYnRuLXN0b3B7YmFja2dyb3VuZDojYjkxYzFjO2NvbG9yOiNmZmZ9CgouYnRuLXJlc3RhcnR7YmFja2dyb3VuZDojYjQ1MzA5O2NvbG9yOiNmZmZ9CgouYnRuLXNhdmV7YmFja2dyb3VuZDojMjU2M2ViO2NvbG9yOiNmZmZ9CgouYnRuLXNhdmVyZXN0YXJ0e2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjNjM2NmYxLCM4YjVjZjYpO2NvbG9yOiNmZmY7Ym94LXNoYWRvdzowIDJweCAxMHB4IHJnYmEoOTksMTAyLDI0MSwwLjMpfQoKLmJ0bi1sb2dvdXR7YmFja2dyb3VuZDp2YXIoLS1idG4tYmcpO2NvbG9yOnZhcigtLXRleHQtc3ViKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcil9CgoKCi8qIFN0YXRzIGJhciAqLwoKLnN0YXRzLWJhcntiYWNrZ3JvdW5kOnZhcigtLWJnLWhlYWRlci1hbHBoYSk7YmFja2Ryb3AtZmlsdGVyOmJsdXIoOHB4KTtwYWRkaW5nOjhweCAyMHB4O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjE0cHg7ZmxleC13cmFwOndyYXA7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTtmbGV4LXNocmluazowO2ZvbnQtc2l6ZToxMnB4fQoKLnN0YXQtaXRlbXtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo1cHg7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCl9Cgouc3RhdC1pdGVtIC5sYWJlbHtjb2xvcjp2YXIoLS10ZXh0LW11dGVkKTtmb250LXNpemU6MTFweH0KCi5zdGF0LWl0ZW0gLnZhbHVle2NvbG9yOnZhcigtLXRleHQtbWFpbik7Zm9udC13ZWlnaHQ6NjAwO2ZvbnQtZmFtaWx5Om1vbm9zcGFjZX0KCi5zdGF0cy1iYXIgLnNlcHtjb2xvcjojMzM0MTU1O2ZvbnQtc2l6ZToxNHB4O3VzZXItc2VsZWN0Om5vbmV9CgoKCi8qIE1haW4gQXJlYSAqLwoKLm1haW57ZmxleDoxIDEgMDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246cm93O3BhZGRpbmc6MTJweCAxNnB4O21pbi1oZWlnaHQ6MDtvdmVyZmxvdzpoaWRkZW47Z2FwOjEwcHh9CgoubWFpbi1sZWZ0e2ZsZXg6MTtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO21pbi13aWR0aDowO2JhY2tncm91bmQ6dmFyKC0tYmctY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6MTBweDtvdmVyZmxvdzpoaWRkZW59CgouZGl2aWRlcnt3aWR0aDo2cHg7Y3Vyc29yOmNvbC1yZXNpemU7YmFja2dyb3VuZDp0cmFuc3BhcmVudDtmbGV4LXNocmluazowO3Bvc2l0aW9uOnJlbGF0aXZlO21hcmdpbjowIC0zcHg7ei1pbmRleDoxMH0KCi5kaXZpZGVyOmhvdmVyLC5kaXZpZGVyLmFjdGl2ZXtiYWNrZ3JvdW5kOnZhcigtLXByaW1hcnkpfQoKLmRpdmlkZXI6OmFmdGVye2NvbnRlbnQ6IiI7cG9zaXRpb246YWJzb2x1dGU7dG9wOjUwJTtsZWZ0OjUwJTt3aWR0aDoycHg7aGVpZ2h0OjMycHg7YmFja2dyb3VuZDojNDc1NTY5O3RyYW5zZm9ybTp0cmFuc2xhdGUoLTUwJSwtNTAlKTtib3JkZXItcmFkaXVzOjJweH0KCi5tYWluLXJpZ2h0e3dpZHRoOjQyJTtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO21pbi13aWR0aDowO2JhY2tncm91bmQ6dmFyKC0tYmctY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6MTBweDtvdmVyZmxvdzpoaWRkZW59CgoKCi8qIExlZnQgUGFuZSBOYXYgKi8KCi52aWV3LW1vZGUtYmFye3BhZGRpbmc6OHB4IDEycHg7YmFja2dyb3VuZDp2YXIoLS1iZy1oZWFkZXIpO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtnYXA6MTBweDtmbGV4LXNocmluazowfQoKLm1vZGUtdGFic3tkaXNwbGF5OmZsZXg7Z2FwOjRweDtiYWNrZ3JvdW5kOnZhcigtLWJnLW1haW4pO3BhZGRpbmc6M3B4O2JvcmRlci1yYWRpdXM6OHB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKX0KCi5tb2RlLXRhYi1idG57cGFkZGluZzo1cHggMTRweDtib3JkZXI6bm9uZTtiYWNrZ3JvdW5kOnRyYW5zcGFyZW50O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2ZvbnQtc2l6ZToxM3B4O2ZvbnQtd2VpZ2h0OjYwMDtib3JkZXItcmFkaXVzOjZweDtjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOmFsbCAuMTVzfQoKLm1vZGUtdGFiLWJ0bi5hY3RpdmV7YmFja2dyb3VuZDp2YXIoLS1wcmltYXJ5KTtjb2xvcjp2YXIoLS10ZXh0LW1haW4pO2JveC1zaGFkb3c6MCAxcHggM3B4IHJnYmEoMCwwLDAsMC4zKX0KCgoKLyogR1VJIFN1YnRhYnMgKi8KCi5ndWktc3VidGFic3tkaXNwbGF5OmZsZXg7Z2FwOjZweDtwYWRkaW5nOjhweCAxNHB4O2JhY2tncm91bmQ6dmFyKC0tYmctaGVhZGVyKTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO292ZXJmbG93LXg6YXV0bztmbGV4LXNocmluazowfQoKLnN1YnRhYi1idG57cGFkZGluZzo2cHggMTRweDtib3JkZXI6bm9uZTtiYWNrZ3JvdW5kOnRyYW5zcGFyZW50O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2ZvbnQtc2l6ZToxM3B4O2ZvbnQtd2VpZ2h0OjUwMDtib3JkZXItcmFkaXVzOjZweDtjdXJzb3I6cG9pbnRlcjt3aGl0ZS1zcGFjZTpub3dyYXA7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NnB4O3RyYW5zaXRpb246YWxsIC4xNXN9Cgouc3VidGFiLWJ0bjpob3Zlcntjb2xvcjp2YXIoLS10ZXh0LW1haW4pO2JhY2tncm91bmQ6dmFyKC0tYmctaG92ZXIpfQoKLnN1YnRhYi1idG4uYWN0aXZle2NvbG9yOnZhcigtLXRleHQtbWFpbik7YmFja2dyb3VuZDpyZ2JhKDk5LDEwMiwyNDEsMC4yNSk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDk5LDEwMiwyNDEsMC40KTtmb250LXdlaWdodDo2MDB9CgoucGlsbC1jb3VudHtiYWNrZ3JvdW5kOnZhcigtLWJ0bi1iZyk7Y29sb3I6dmFyKC0tdGV4dC1zdWIpO3BhZGRpbmc6MXB4IDZweDtib3JkZXItcmFkaXVzOjEwcHg7Zm9udC1zaXplOjExcHh9CgoKCi8qIEdVSSBDb250ZW50IENvbnRhaW5lciAqLwoKLmd1aS1jb250YWluZXJ7ZmxleDoxIDEgMDtvdmVyZmxvdy15OmF1dG87cGFkZGluZzoxNnB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjE2cHh9CgoudGFiLXBhbmV7ZGlzcGxheTpub25lO2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTZweH0KCi50YWItcGFuZS5hY3RpdmV7ZGlzcGxheTpmbGV4fQoKCgovKiBDYXJkcyAmIEZvcm1zICovCgouZ3VpLWNhcmR7YmFja2dyb3VuZDp2YXIoLS1iZy1oZWFkZXIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjE2cHg7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTRweH0KCi5ndWktY2FyZC1oZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2Vlbjtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO3BhZGRpbmctYm90dG9tOjEwcHh9CgouZ3VpLWNhcmQtdGl0bGV7Zm9udC1zaXplOjE0cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXRleHQtbWFpbik7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4fQoKLmd1aS1jYXJkLWRlc2N7Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7bWFyZ2luLXRvcDoycHh9CgoKCi5mb3JtLWdyaWR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoYXV0by1maXQsbWlubWF4KDI0MHB4LDFmcikpO2dhcDoxNHB4fQoKLmZvcm0tZ3JvdXB7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6NnB4fQoKLmZvcm0tZ3JvdXAuZnVsbHtncmlkLWNvbHVtbjoxLy0xfQoKLmZvcm0tbGFiZWx7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NjAwO2NvbG9yOnZhcigtLXRleHQtc3ViKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVufQoKLmZvcm0tbGFiZWwgc21hbGx7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7Zm9udC13ZWlnaHQ6NDAwfQoKLmZvcm0taW5wdXR7d2lkdGg6MTAwJTtwYWRkaW5nOjlweCAxMnB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyLWxpZ2h0KTtib3JkZXItcmFkaXVzOjZweDtiYWNrZ3JvdW5kOnZhcigtLWJnLWlucHV0KTtjb2xvcjp2YXIoLS10ZXh0LW1haW4pO2ZvbnQtc2l6ZToxM3B4O291dGxpbmU6bm9uZTt0cmFuc2l0aW9uOmFsbCAuMTVzfQoKLmZvcm0taW5wdXQ6Zm9jdXN7Ym9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpO2JveC1zaGFkb3c6MCAwIDAgMnB4IHJnYmEoOTksMTAyLDI0MSwwLjIpfQoKLmZvcm0tc2VsZWN0e3dpZHRoOjEwMCU7cGFkZGluZzo5cHggMTJweDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlci1saWdodCk7Ym9yZGVyLXJhZGl1czo2cHg7YmFja2dyb3VuZDp2YXIoLS1iZy1pbnB1dCk7Y29sb3I6dmFyKC0tdGV4dC1tYWluKTtmb250LXNpemU6MTNweDtvdXRsaW5lOm5vbmV9CgoKCi5pbnB1dC13aXRoLWFjdGlvbntkaXNwbGF5OmZsZXg7Z2FwOjZweH0KCi5pbnB1dC13aXRoLWFjdGlvbiAuZm9ybS1pbnB1dHtmbGV4OjF9CgouYnRuLW1pbml7cGFkZGluZzo2cHggMTBweDtiYWNrZ3JvdW5kOnZhcigtLWJ0bi1iZyk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6NnB4O2NvbG9yOnZhcigtLXRleHQtc3ViKTtjdXJzb3I6cG9pbnRlcjtmb250LXNpemU6MTJweDtkaXNwbGF5OmlubGluZS1mbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO3RyYW5zaXRpb246YWxsIC4xNXN9CgouYnRuLW1pbmk6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1idG4taG92ZXIpO2NvbG9yOnZhcigtLXRleHQtbWFpbil9CgoKCi50b2dnbGUtc3dpdGNoe3Bvc2l0aW9uOnJlbGF0aXZlO2Rpc3BsYXk6aW5saW5lLWJsb2NrO3dpZHRoOjM4cHg7aGVpZ2h0OjIwcHh9CgoudG9nZ2xlLXN3aXRjaCBpbnB1dHtvcGFjaXR5OjA7d2lkdGg6MDtoZWlnaHQ6MH0KCi50b2dnbGUtc2xpZGVye3Bvc2l0aW9uOmFic29sdXRlO2N1cnNvcjpwb2ludGVyO3RvcDowO2xlZnQ6MDtyaWdodDowO2JvdHRvbTowO2JhY2tncm91bmQtY29sb3I6IzQ3NTU2OTt0cmFuc2l0aW9uOi4ycztib3JkZXItcmFkaXVzOjIwcHh9CgoudG9nZ2xlLXNsaWRlcjpiZWZvcmV7cG9zaXRpb246YWJzb2x1dGU7Y29udGVudDoiIjtoZWlnaHQ6MTRweDt3aWR0aDoxNHB4O2xlZnQ6M3B4O2JvdHRvbTozcHg7YmFja2dyb3VuZC1jb2xvcjp3aGl0ZTt0cmFuc2l0aW9uOi4ycztib3JkZXItcmFkaXVzOjUwJX0KCmlucHV0OmNoZWNrZWQgKyAudG9nZ2xlLXNsaWRlcntiYWNrZ3JvdW5kLWNvbG9yOnZhcigtLXByaW1hcnkpfQoKaW5wdXQ6Y2hlY2tlZCArIC50b2dnbGUtc2xpZGVyOmJlZm9yZXt0cmFuc2Zvcm06dHJhbnNsYXRlWCgxOHB4KX0KCgoKLyogT3V0Ym91bmRzIExpc3QgKi8KCi5vdXRib3VuZC1saXN0e2Rpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMjgwcHgsMWZyKSk7Z2FwOjEycHh9Cgoub2ItY2FyZHtiYWNrZ3JvdW5kOnZhcigtLWJnLXN1YmNhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjE0cHg7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTBweDtwb3NpdGlvbjpyZWxhdGl2ZTt0cmFuc2l0aW9uOmFsbCAuMTVzfQoKLm9iLWNhcmQ6aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpO2JveC1zaGFkb3c6MCA0cHggMTZweCByZ2JhKDAsMCwwLDAuMyl9Cgoub2ItY2FyZC10b3B7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2Vlbn0KCi5vYi1uYW1le2ZvbnQtc2l6ZToxNHB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS10ZXh0LW1haW4pfQoKLm9iLWJhZGdle3BhZGRpbmc6MnB4IDhweDtib3JkZXItcmFkaXVzOjRweDtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo2MDB9Cgoub2ItYmFkZ2Uuc29ja3M1e2JhY2tncm91bmQ6cmdiYSg1NiwxODksMjQ4LDAuMTUpO2NvbG9yOiMzOGJkZjg7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDU2LDE4OSwyNDgsMC4zKX0KCi5vYi1iYWRnZS5kaXJlY3R7YmFja2dyb3VuZDpyZ2JhKDM0LDE5Nyw5NCwwLjE1KTtjb2xvcjojMjJjNTVlO2JvcmRlcjoxcHggc29saWQgcmdiYSgzNCwxOTcsOTQsMC4zKX0KCi5vYi1iYWRnZS5odHRwe2JhY2tncm91bmQ6cmdiYSgxNjgsODUsMjQ3LDAuMTUpO2NvbG9yOiNjMDg0ZmM7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDE2OCw4NSwyNDcsMC4zKX0KCi5vYi1kZXRhaWxze2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjRweDtmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10ZXh0LW11dGVkKTtmb250LWZhbWlseTptb25vc3BhY2V9Cgoub2ItYWN0aW9uc3tkaXNwbGF5OmZsZXg7Z2FwOjZweDtqdXN0aWZ5LWNvbnRlbnQ6ZmxleC1lbmQ7bWFyZ2luLXRvcDo2cHg7Ym9yZGVyLXRvcDoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtwYWRkaW5nLXRvcDo4cHh9CgoKCi8qIEFDTCBUYWJsZSAqLwoKLmFjbC10YWJsZXt3aWR0aDoxMDAlO2JvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtmb250LXNpemU6MTNweH0KCi5hY2wtdGFibGUgdGh7dGV4dC1hbGlnbjpsZWZ0O3BhZGRpbmc6OHB4IDEycHg7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7Zm9udC13ZWlnaHQ6NjAwO2ZvbnQtc2l6ZToxMXB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7YmFja2dyb3VuZDojMTMxYzJlfQoKLmFjbC10YWJsZSB0ZHtwYWRkaW5nOjhweCAxMnB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Y29sb3I6dmFyKC0tdGV4dC1zdWIpO2ZvbnQtZmFtaWx5Om1vbm9zcGFjZX0KCi5hY2wtdGFibGUgdHI6aG92ZXIgdGR7YmFja2dyb3VuZDp2YXIoLS1iZy1ob3Zlcil9CgouYWNsLXRhZ3tkaXNwbGF5OmlubGluZS1ibG9jaztwYWRkaW5nOjJweCA4cHg7Ym9yZGVyLXJhZGl1czo0cHg7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NjAwO2JhY2tncm91bmQ6cmdiYSg5OSwxMDIsMjQxLDAuMTUpO2NvbG9yOiNhNWI0ZmM7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDk5LDEwMiwyNDEsMC4zKX0KCgoKLyogUmF3IEVkaXRvciAqLwoKI3Jhdy1wYW5le2ZsZXg6MSAxIDA7ZGlzcGxheTpub25lO2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjttaW4taGVpZ2h0OjA7cGFkZGluZzoxMnB4fQoKI3Jhdy1wYW5lLmFjdGl2ZXtkaXNwbGF5OmZsZXh9CgojY29uZmlnLWVkaXRvcntmbGV4OjEgMSAwO3dpZHRoOjEwMCU7YmFja2dyb3VuZDp2YXIoLS1iZy1tYWluKTtjb2xvcjp2YXIoLS10ZXh0LXN1Yik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6NnB4O2ZvbnQtZmFtaWx5OidDYXNjYWRpYSBDb2RlJywnRmlyYSBDb2RlJywnQ29uc29sYXMnLG1vbm9zcGFjZTtmb250LXNpemU6MTNweDtsaW5lLWhlaWdodDoxLjY7cGFkZGluZzoxMnB4O3Jlc2l6ZTpub25lO291dGxpbmU6bm9uZTt0YWItc2l6ZToyfQoKI2NvbmZpZy1lZGl0b3I6Zm9jdXN7Ym9yZGVyLWNvbG9yOnZhcigtLXByaW1hcnkpfQoKCgovKiBSaWdodCBQYW5lIC0gTG9ncyAmIFN0cmVhbXMgKi8KCi5sb2ctYmFye3BhZGRpbmc6OHB4IDEycHg7YmFja2dyb3VuZDp2YXIoLS1iZy1oZWFkZXIpO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtmbGV4LXNocmluazowfQoKLnRhYi1idG57YmFja2dyb3VuZDpub25lO2JvcmRlcjpub25lO2N1cnNvcjpwb2ludGVyO2ZvbnQtc2l6ZToxM3B4O2ZvbnQtd2VpZ2h0OjYwMDtwYWRkaW5nOjRweCAxMHB4O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2JvcmRlci1yYWRpdXM6NnB4O3RyYW5zaXRpb246YWxsIC4xNXN9CgoudGFiLWJ0bi5hY3RpdmV7Y29sb3I6dmFyKC0tdGV4dC1tYWluKTtiYWNrZ3JvdW5kOnZhcigtLWJ0bi1iZyl9CgoubG9nLWNvbnRyb2xze2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweH0KCiNsb2ctY29udGVudHtmbGV4OjEgMSAwO21pbi1oZWlnaHQ6MDtiYWNrZ3JvdW5kOnZhcigtLWJnLW1haW4pO2NvbG9yOnZhcigtLXRleHQtbWFpbik7Zm9udC1mYW1pbHk6J0Nhc2NhZGlhIENvZGUnLCdGaXJhIENvZGUnLCdDb25zb2xhcycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMnB4O2xpbmUtaGVpZ2h0OjEuNTtwYWRkaW5nOjEwcHg7b3ZlcmZsb3cteTphdXRvO3doaXRlLXNwYWNlOnByZS13cmFwO3dvcmQtYnJlYWs6YnJlYWstYWxsfQoKI2Nvbm4tY29udGVudHtmbGV4OjEgMSAwO21pbi1oZWlnaHQ6MDtvdmVyZmxvdy15OmF1dG87YmFja2dyb3VuZDp2YXIoLS1iZy1tYWluKX0KCi5jb25uLXN1bW1hcnl7cGFkZGluZzoxMHB4IDE0cHg7Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7ZGlzcGxheTpmbGV4O2dhcDoxNnB4O2ZsZXgtd3JhcDp3cmFwO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7YmFja2dyb3VuZDojMTMxYzJlfQoKLmNvbm4tc3VtbWFyeSBie2NvbG9yOnZhcigtLXRleHQtbWFpbil9CgouY29ubi10YWJsZXt3aWR0aDoxMDAlO2JvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtmb250LXNpemU6MTJweH0KCi5jb25uLXRhYmxlIHRoe3RleHQtYWxpZ246bGVmdDtwYWRkaW5nOjhweCAxMHB4O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2ZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MTFweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JhY2tncm91bmQ6IzEzMWMyZX0KCi5jb25uLXRhYmxlIHRke3BhZGRpbmc6NnB4IDEwcHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTtjb2xvcjp2YXIoLS10ZXh0LXN1Yik7Zm9udC1mYW1pbHk6bW9ub3NwYWNlO3dvcmQtYnJlYWs6YnJlYWstYWxsfQoKLmNvbm4tdGFibGUgdHI6aG92ZXIgdGR7YmFja2dyb3VuZDp2YXIoLS1iZy1ob3Zlcil9CgouY29ubi10YWJsZSB0ZC5udW17dGV4dC1hbGlnbjpyaWdodDt3aGl0ZS1zcGFjZTpub3dyYXB9CgouY29ubi10YWJsZSB0ZC50eHtjb2xvcjojNjBhNWZhfQoKLmNvbm4tdGFibGUgdGQucnh7Y29sb3I6IzRhZGU4MH0KCi5jb25uLWVtcHR5e3BhZGRpbmc6MzBweDt0ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjp2YXIoLS10ZXh0LW11dGVkKTtmb250LXNpemU6MTNweH0KCgoKLyogTW9kYWwgRGlhbG9ncyAqLwoKLm1vZGFsLW92ZXJsYXl7cG9zaXRpb246Zml4ZWQ7dG9wOjA7bGVmdDowO3JpZ2h0OjA7Ym90dG9tOjA7YmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuNyk7YmFja2Ryb3AtZmlsdGVyOmJsdXIoNHB4KTtkaXNwbGF5Om5vbmU7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7ei1pbmRleDo5OTk5fQoKLm1vZGFsLW92ZXJsYXkuc2hvd3tkaXNwbGF5OmZsZXh9CgoubW9kYWwtYm94e2JhY2tncm91bmQ6dmFyKC0tYmctY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXItbGlnaHQpO2JvcmRlci1yYWRpdXM6MTJweDtib3gtc2hhZG93OjAgMTJweCA0MHB4IHJnYmEoMCwwLDAsMC42KTt3aWR0aDo0NjBweDttYXgtd2lkdGg6OTIlO3BhZGRpbmc6MjJweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDoxNnB4fQoKLm1vZGFsLWhlYWRlcntkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7cGFkZGluZy1ib3R0b206MTBweH0KCi5tb2RhbC10aXRsZXtmb250LXNpemU6MTVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdGV4dC1tYWluKX0KCi5tb2RhbC1mb290ZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6ZmxleC1lbmQ7Z2FwOjhweDtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO3BhZGRpbmctdG9wOjE0cHh9CgoKCi8qIFRvYXN0IEFsZXJ0ICovCgojYWxlcnQtYm94e3Bvc2l0aW9uOmZpeGVkO3RvcDoxNnB4O2xlZnQ6NTAlO3RyYW5zZm9ybTp0cmFuc2xhdGVYKC01MCUpO3BhZGRpbmc6MTBweCAyNHB4O2JvcmRlci1yYWRpdXM6OHB4O2ZvbnQtc2l6ZToxM3B4O2ZvbnQtd2VpZ2h0OjYwMDt6LWluZGV4OjEwMDAwO29wYWNpdHk6MDt0cmFuc2l0aW9uOm9wYWNpdHkgLjI1cyx0cmFuc2Zvcm0gLjI1cztwb2ludGVyLWV2ZW50czpub25lO21heC13aWR0aDo5MCU7Ym94LXNoYWRvdzowIDZweCAyMHB4IHJnYmEoMCwwLDAsMC40KX0KCiNhbGVydC1ib3guc2hvd3tvcGFjaXR5OjE7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSg1cHgpfQoKLmFsZXJ0LW9re2JhY2tncm91bmQ6IzA2NWY0Njtjb2xvcjojMzRkMzk5O2JvcmRlcjoxcHggc29saWQgIzA1OTY2OX0KCi5hbGVydC1lcnJ7YmFja2dyb3VuZDojODgxMzM3O2NvbG9yOiNmYjcxODU7Ym9yZGVyOjFweCBzb2xpZCAjYmUxMjNjfQoKLmFsZXJ0LWluZm97YmFja2dyb3VuZDojMWUzYThhO2NvbG9yOiM5M2M1ZmQ7Ym9yZGVyOjFweCBzb2xpZCAjMjU2M2VifQoKCi5idG4tdXBkYXRle2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEzNWRlZywjMGQ5NDg4LCMwZjc2NmUpO2NvbG9yOiNmZmY7Ym94LXNoYWRvdzowIDJweCA4cHggcmdiYSgxMywxNDgsMTM2LDAuMyl9Cjwvc3R5bGU+Cgo8L2hlYWQ+Cgo8Ym9keT4KCjxkaXYgaWQ9ImFsZXJ0LWJveCI+PC9kaXY+CgoKCjwhLS0gTW9kYWw6IE91dGJvdW5kIC0tPgoKPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSIgaWQ9Im1vZGFsLW91dGJvdW5kIj4KCiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1ib3giPgoKICAgICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1oZWFkZXIiPgoKICAgICAgICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtdGl0bGUiIGlkPSJtb2RhbC1vYi10aXRsZSI+5re75Yqg5Ye656uZ6IqC54K5PC9kaXY+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0iY2xvc2VNb2RhbCgnbW9kYWwtb3V0Ym91bmQnKSI+JiMxMDAwNTs8L2J1dHRvbj4KCiAgICAgICAgPC9kaXY+CgogICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEycHgiPgoKICAgICAgICAgICAgPGlucHV0IHR5cGU9ImhpZGRlbiIgaWQ9Im1vZGFsLW9iLWlkeCIgdmFsdWU9Ii0xIj4KCiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+6IqC54K55qCH6K+G5ZCN56ewIChOYW1lKSAqPC9sYWJlbD4KCiAgICAgICAgICAgICAgICA8aW5wdXQgY2xhc3M9ImZvcm0taW5wdXQiIGlkPSJtb2RhbC1vYi1uYW1lIiBwbGFjZWhvbGRlcj0i5L6L5aaCOiBoa19zb2NrcywgdG9yLCBub2RlMSI+CgogICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+6IqC54K557G75Z6LIChUeXBlKSAqPC9sYWJlbD4KCiAgICAgICAgICAgICAgICA8c2VsZWN0IGNsYXNzPSJmb3JtLXNlbGVjdCIgaWQ9Im1vZGFsLW9iLXR5cGUiIG9uY2hhbmdlPSJ1cGRhdGVPdXRib3VuZE1vZGFsRmllbGRzKCkiPgoKICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJzb2NrczUiPlNvY2tzNSDku6PnkIblh7rnq5k8L29wdGlvbj4KCiAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZGlyZWN0Ij5EaXJlY3Qg5pys5Zyw55u06L+ePC9vcHRpb24+CgogICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9Imh0dHAiPkhUVFAg5Luj55CG5Ye656uZPC9vcHRpb24+CgogICAgICAgICAgICAgICAgPC9zZWxlY3Q+CgogICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgIDwhLS0gU29ja3M1IC8gSFRUUCBGaWVsZHMgLS0+CgogICAgICAgICAgICA8ZGl2IGlkPSJtb2RhbC1vYi1wcm94eS1maWVsZHMiIHN0eWxlPSJkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDoxMnB4Ij4KCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj4KCiAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7mnI3liqHlmajlnLDlnYAgKEhvc3Q6UG9ydCkgKjwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Im1vZGFsLW9iLWFkZHIiIHBsYWNlaG9sZGVyPSLkvovlpoI6IDE5OC41MS4xMDAuMToxMDgwIOaIliBkb21haW4uY29tOjEwODAiPgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZvcm0tbGFiZWwiPuiupOivgeeUqOaIt+WQjSAo5Y+v6YCJKTwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Im1vZGFsLW9iLXVzZXIiIHBsYWNlaG9sZGVyPSLnlZnnqbrliJnml6DorqTor4EiPgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZvcm0tbGFiZWwiPuiupOivgeWvhueggSAo5Y+v6YCJKTwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Im1vZGFsLW9iLXBhc3MiIHBsYWNlaG9sZGVyPSLnlZnnqbrliJnml6DorqTor4EiPgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8IS0tIERpcmVjdCBGaWVsZHMgLS0+CgogICAgICAgICAgICA8ZGl2IGlkPSJtb2RhbC1vYi1kaXJlY3QtZmllbGRzIiBzdHlsZT0iZGlzcGxheTpub25lO2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTJweCI+CgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+5Ye656uZIElQIOaooeW8jyAoTW9kZSk8L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICA8c2VsZWN0IGNsYXNzPSJmb3JtLXNlbGVjdCIgaWQ9Im1vZGFsLW9iLW1vZGUiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iNCI+NCAo5LuFIElQdjQpPC9vcHRpb24+CgogICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI2Ij42ICjku4UgSVB2Nik8L29wdGlvbj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImF1dG8iPmF1dG8gKOiHquWKqOmAieaLqSk8L29wdGlvbj4KCiAgICAgICAgICAgICAgICAgICAgPC9zZWxlY3Q+CgogICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgPC9kaXY+CgogICAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWZvb3RlciI+CgogICAgICAgICAgICAKCiAgICAgICAgPGRpdiBjbGFzcz0idGhlbWUtc3dpdGNoZXIiPgoKICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGhlbWUtYnRuIiBpZD0idGhlbWUtYnRuLWRhcmsiIG9uY2xpY2s9InNldFRoZW1lKCdkYXJrJykiIHRpdGxlPSLmt7HoibLmqKHlvI8iPiYjMTI3NzY5OyDmt7HoibI8L2J1dHRvbj4KCiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRoZW1lLWJ0biIgaWQ9InRoZW1lLWJ0bi1saWdodCIgb25jbGljaz0ic2V0VGhlbWUoJ2xpZ2h0JykiIHRpdGxlPSLmtYXoibLmqKHlvI8iPiYjOTcyODsmIzY1MDM5OyDmtYXoibI8L2J1dHRvbj4KCiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRoZW1lLWJ0biIgaWQ9InRoZW1lLWJ0bi1hdXRvIiBvbmNsaWNrPSJzZXRUaGVtZSgnYXV0bycpIiB0aXRsZT0i6Lef6ZqP57O757ufIj4mIzEyNzc2Mzsg6Ieq5YqoPC9idXR0b24+CgogICAgICAgIDwvZGl2PgoKCgogICAgICAgIAogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXVwZGF0ZSIgb25jbGljaz0idXBkYXRlSHkyKCkiIHRpdGxlPSLljYfnuqcgSHlzdGVyaWEgMiDmoLjlv4PliLDmnIDmlrDniYjmnKwiPgogICAgICAgICAgICAgICAgPHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIHdpZHRoPSIxNCIgaGVpZ2h0PSIxNCIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMiIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTQgMTZ2MWEzIDMgMCAwIDAgMyAzaDEwYTMgMyAwIDAgMCAzLTN2LTFNMTYgMTBsLTQgNC00LTRNMTIgNHYxMCIvPjwvc3ZnPgogICAgICAgICAgICAgICAg5pu05paw5qC45b+DCiAgICAgICAgICAgIDwvYnV0dG9uPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWxvZ291dCIgb25jbGljaz0iY2xvc2VNb2RhbCgnbW9kYWwtb3V0Ym91bmQnKSI+5Y+W5raIPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNhdmUiIG9uY2xpY2s9InNhdmVPdXRib3VuZE1vZGFsKCkiPuehruWumuS/neWtmDwvYnV0dG9uPgoKICAgICAgICA8L2Rpdj4KCiAgICA8L2Rpdj4KCjwvZGl2PgoKCgo8IS0tIE1vZGFsOiBBQ0wgUnVsZSAtLT4KCjxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkiIGlkPSJtb2RhbC1hY2wiPgoKICAgIDxkaXYgY2xhc3M9Im1vZGFsLWJveCI+CgogICAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWhlYWRlciI+CgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJtb2RhbC10aXRsZSIgaWQ9Im1vZGFsLWFjbC10aXRsZSI+5re75Yqg5YiG5rWB6KeE5YiZPC9kaXY+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0iY2xvc2VNb2RhbCgnbW9kYWwtYWNsJykiPiYjMTAwMDU7PC9idXR0b24+CgogICAgICAgIDwvZGl2PgoKICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDoxMnB4Ij4KCiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJoaWRkZW4iIGlkPSJtb2RhbC1hY2wtaWR4IiB2YWx1ZT0iLTEiPgoKICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7nm67moIflh7rnq5noioLngrkgKFRhcmdldCBPdXRib3VuZCkgKjwvbGFiZWw+CgogICAgICAgICAgICAgICAgPHNlbGVjdCBjbGFzcz0iZm9ybS1zZWxlY3QiIGlkPSJtb2RhbC1hY2wtb3V0Ym91bmQiPgoKICAgICAgICAgICAgICAgICAgICA8IS0tIFBvcHVsYXRlZCBkeW5hbWljYWxseSAtLT4KCiAgICAgICAgICAgICAgICA8L3NlbGVjdD4KCiAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7lv6vmjbfop4TliJnnsbvlnovliqnmiYs8L2xhYmVsPgoKICAgICAgICAgICAgICAgIDxzZWxlY3QgY2xhc3M9ImZvcm0tc2VsZWN0IiBpZD0ibW9kYWwtYWNsLWhlbHBlciIgb25jaGFuZ2U9ImFwcGx5QWNsSGVscGVyKCkiPgoKICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIiPi0tIOmAieaLqeW4uOeUqOinhOWImemihOiuvuaooeadvyAtLTwvb3B0aW9uPgoKICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJzdWZmaXg6b25pb24iPua0i+iRsee9kee7nOWfn+WQjSAoc3VmZml4Om9uaW9uKTwvb3B0aW9uPgoKICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJnZW9pcDpjbiI+5Lit5Zu95aSn6ZmGIElQIChnZW9pcDpjbik8L29wdGlvbj4KCiAgICAgICAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZ2VvaXA6dGVsZWdyYW0iPlRlbGVncmFtIOWumOaWuSBJUCDmrrUgKGdlb2lwOnRlbGVncmFtKTwvb3B0aW9uPgoKICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSI6Oi8wIj7lhajph48gSVB2NiDmtYHph48gKDo6LzApPC9vcHRpb24+CgogICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjAuMC4wLjAvMCI+5YWo6YePIElQdjQg5rWB6YePICgwLjAuMC4wLzApPC9vcHRpb24+CgogICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImFsbCI+5YWc5bqV5YWo5bGA6KeE5YiZIChhbGwpPC9vcHRpb24+CgogICAgICAgICAgICAgICAgPC9zZWxlY3Q+CgogICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+5Yy56YWN6KGo6L6+5byPIChSdWxlIEV4cHJlc3Npb24pICo8L2xhYmVsPgoKICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Im1vZGFsLWFjbC1ydWxlIiBwbGFjZWhvbGRlcj0i5L6L5aaCOiBzdWZmaXg6b25pb24sIDAuMC4wLjAvMCwgKi5leGFtcGxlLmNvbSwgYWxsIj4KCiAgICAgICAgICAgICAgICA8c21hbGwgc3R5bGU9ImNvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2ZvbnQtc2l6ZToxMXB4Ij7mlK/mjIE6IElQL0NJRFIgKOWmgiAwLjAuMC4wLzAsIDo6LzApLCDln5/lkI3pgJrphY0gKCouZ29vZ2xlLmNvbSksIOWQjue8gCAoc3VmZml4Om9uaW9uKSwgR2VvSVAgKGdlb2lwOmNuKSwg5YWc5bqVIChhbGwpPC9zbWFsbD4KCiAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICA8L2Rpdj4KCiAgICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtZm9vdGVyIj4KCiAgICAgICAgICAgIAoKICAgICAgICA8ZGl2IGNsYXNzPSJ0aGVtZS1zd2l0Y2hlciI+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aGVtZS1idG4iIGlkPSJ0aGVtZS1idG4tZGFyayIgb25jbGljaz0ic2V0VGhlbWUoJ2RhcmsnKSIgdGl0bGU9Iua3seiJsuaooeW8jyI+JiMxMjc3Njk7IOa3seiJsjwvYnV0dG9uPgoKICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGhlbWUtYnRuIiBpZD0idGhlbWUtYnRuLWxpZ2h0IiBvbmNsaWNrPSJzZXRUaGVtZSgnbGlnaHQnKSIgdGl0bGU9Iua1heiJsuaooeW8jyI+JiM5NzI4OyYjNjUwMzk7IOa1heiJsjwvYnV0dG9uPgoKICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGhlbWUtYnRuIiBpZD0idGhlbWUtYnRuLWF1dG8iIG9uY2xpY2s9InNldFRoZW1lKCdhdXRvJykiIHRpdGxlPSLot5/pmo/ns7vnu58iPiYjMTI3NzYzOyDoh6rliqg8L2J1dHRvbj4KCiAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgCiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tdXBkYXRlIiBvbmNsaWNrPSJ1cGRhdGVIeTIoKSIgdGl0bGU9IuWNh+e6pyBIeXN0ZXJpYSAyIOaguOW/g+WIsOacgOaWsOeJiOacrCI+CiAgICAgICAgICAgICAgICA8c3ZnIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjE0IiBoZWlnaHQ9IjE0IiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBmaWxsPSJub25lIj48cGF0aCBkPSJNNCAxNnYxYTMgMyAwIDAgMCAzIDNoMTBhMyAzIDAgMCAwIDMtM3YtMU0xNiAxMGwtNCA0LTQtNE0xMiA0djEwIi8+PC9zdmc+CiAgICAgICAgICAgICAgICDmm7TmlrDmoLjlv4MKICAgICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tbG9nb3V0IiBvbmNsaWNrPSJjbG9zZU1vZGFsKCdtb2RhbC1hY2wnKSI+5Y+W5raIPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNhdmUiIG9uY2xpY2s9InNhdmVBY2xNb2RhbCgpIj7noa7lrprkv53lrZg8L2J1dHRvbj4KCiAgICAgICAgPC9kaXY+CgogICAgPC9kaXY+Cgo8L2Rpdj4KCgoKPCEtLSBIZWFkZXIgLS0+Cgo8ZGl2IGNsYXNzPSJoZWFkZXIiPgoKICAgIDxkaXYgY2xhc3M9ImhlYWRlci1sZWZ0Ij4KCiAgICAgICAgPGgxPjxzcGFuPiYjOTg4OTs8L3NwYW4+IEh5c3RlcmlhIDI8L2gxPgoKICAgICAgICA8ZGl2IGNsYXNzPSJiYWRnZS1zdGF0dXMiIGlkPSJzdGF0dXMtYmFkZ2UiPjxzcGFuIGNsYXNzPSJkb3QtcHVsc2UiPjwvc3Bhbj4gPHNwYW4gaWQ9InN0YXR1cy10ZXh0Ij7mo4Dmn6XkuK0uLi48L3NwYW4+PC9kaXY+CgogICAgPC9kaXY+CgogICAgPGRpdiBjbGFzcz0icmlnaHQtYmFyIj4KCiAgICAgICAgPGRpdiBjbGFzcz0iY29udHJvbHMiPgoKICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zdGFydCIgb25jbGljaz0iY29udHJvbFNlcnZpY2UoJ3N0YXJ0JykiIHRpdGxlPSLlkK/liqjmnI3liqEiPiYjOTY1NDsg5byA5ZCvPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXN0b3AiIG9uY2xpY2s9ImNvbnRyb2xTZXJ2aWNlKCdzdG9wJykiIHRpdGxlPSLlgZzmraLmnI3liqEiPiYjOTYzMjsg5YWz6ZetPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXJlc3RhcnQiIG9uY2xpY2s9ImNvbnRyb2xTZXJ2aWNlKCdyZXN0YXJ0JykiIHRpdGxlPSLph43lkK/mnI3liqEiPiYjODYzNTsg6YeN5ZCvPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNhdmUiIG9uY2xpY2s9InNhdmVBY3RpdmVDb25maWcoZmFsc2UpIiB0aXRsZT0i5L+d5a2Y5b2T5YmN6YWN572uIj4mIzEyODE5MDsg5L+d5a2Y6YWN572uPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNhdmVyZXN0YXJ0IiBvbmNsaWNrPSJzYXZlQWN0aXZlQ29uZmlnKHRydWUpIiB0aXRsZT0i5L+d5a2Y5bm256uL5Y2z6YeN5ZCv5pyN5Yqh55Sf5pWIIj4mIzk4ODk7IOS/neWtmOW5tumHjeWQrzwvYnV0dG9uPgoKICAgICAgICA8L2Rpdj4KCiAgICAgICAgCgogICAgICAgIDxkaXYgY2xhc3M9InRoZW1lLXN3aXRjaGVyIj4KCiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InRoZW1lLWJ0biIgaWQ9InRoZW1lLWJ0bi1kYXJrIiBvbmNsaWNrPSJzZXRUaGVtZSgnZGFyaycpIiB0aXRsZT0i5rex6Imy5qih5byPIj4mIzEyNzc2OTsg5rex6ImyPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aGVtZS1idG4iIGlkPSJ0aGVtZS1idG4tbGlnaHQiIG9uY2xpY2s9InNldFRoZW1lKCdsaWdodCcpIiB0aXRsZT0i5rWF6Imy5qih5byPIj4mIzk3Mjg7JiM2NTAzOTsg5rWF6ImyPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0aGVtZS1idG4iIGlkPSJ0aGVtZS1idG4tYXV0byIgb25jbGljaz0ic2V0VGhlbWUoJ2F1dG8nKSIgdGl0bGU9Iui3n+maj+ezu+e7nyI+JiMxMjc3NjM7IOiHquWKqDwvYnV0dG9uPgoKICAgICAgICA8L2Rpdj4KCgoKICAgICAgICAKICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi11cGRhdGUiIG9uY2xpY2s9InVwZGF0ZUh5MigpIiB0aXRsZT0i5Y2H57qnIEh5c3RlcmlhIDIg5qC45b+D5Yiw5pyA5paw54mI5pysIj4KICAgICAgICAgICAgICAgIDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiB3aWR0aD0iMTQiIGhlaWdodD0iMTQiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lkdGg9IjIiIGZpbGw9Im5vbmUiPjxwYXRoIGQ9Ik00IDE2djFhMyAzIDAgMCAwIDMgM2gxMGEzIDMgMCAwIDAgMy0zdi0xTTE2IDEwbC00IDQtNC00TTEyIDR2MTAiLz48L3N2Zz4KICAgICAgICAgICAgICAgIOabtOaWsOaguOW/gwogICAgICAgICAgICA8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1sb2dvdXQiIG9uY2xpY2s9ImxvY2F0aW9uLmhyZWY9Jy9sb2dvdXQnIj4mIzEyODI3NDsg6YCA5Ye6PC9idXR0b24+CgogICAgPC9kaXY+Cgo8L2Rpdj4KCgoKPCEtLSBTeXN0ZW0gU3RhdHMgLS0+Cgo8ZGl2IGNsYXNzPSJzdGF0cy1iYXIiPgoKICAgIDxzcGFuIGNsYXNzPSJzdGF0LWl0ZW0iPjxzcGFuIGNsYXNzPSJsYWJlbCI+Q1BVPC9zcGFuPjxzcGFuIGNsYXNzPSJ2YWx1ZSIgaWQ9InNpLWNwdSI+LS08L3NwYW4+PC9zcGFuPgoKICAgIDxzcGFuIGNsYXNzPSJzZXAiPnw8L3NwYW4+CgogICAgPHNwYW4gY2xhc3M9InN0YXQtaXRlbSI+PHNwYW4gY2xhc3M9ImxhYmVsIj7lhoXlrZg8L3NwYW4+PHNwYW4gY2xhc3M9InZhbHVlIiBpZD0ic2ktbWVtIj4tLTwvc3Bhbj48L3NwYW4+CgogICAgPHNwYW4gY2xhc3M9InNlcCI+fDwvc3Bhbj4KCiAgICA8c3BhbiBjbGFzcz0ic3RhdC1pdGVtIj48c3BhbiBjbGFzcz0ibGFiZWwiPuejgeebmDwvc3Bhbj48c3BhbiBjbGFzcz0idmFsdWUiIGlkPSJzaS1kaXNrIj4tLTwvc3Bhbj48L3NwYW4+CgogICAgPHNwYW4gY2xhc3M9InNlcCI+fDwvc3Bhbj4KCiAgICA8c3BhbiBjbGFzcz0ic3RhdC1pdGVtIj48c3BhbiBjbGFzcz0ibGFiZWwiPuS4i+ihjOaAu+mHjzwvc3Bhbj48c3BhbiBjbGFzcz0idmFsdWUiIGlkPSJzaS1yeCI+LS08L3NwYW4+PC9zcGFuPgoKICAgIDxzcGFuIGNsYXNzPSJzZXAiPnw8L3NwYW4+CgogICAgPHNwYW4gY2xhc3M9InN0YXQtaXRlbSI+PHNwYW4gY2xhc3M9ImxhYmVsIj7kuIrooYzmgLvph488L3NwYW4+PHNwYW4gY2xhc3M9InZhbHVlIiBpZD0ic2ktdHgiPi0tPC9zcGFuPjwvc3Bhbj4KCiAgICA8c3BhbiBjbGFzcz0ic2VwIj58PC9zcGFuPgoKICAgIDxzcGFuIGNsYXNzPSJzdGF0LWl0ZW0iPjxzcGFuIGNsYXNzPSJsYWJlbCI+5LiL6KGM6YCf5bqmPC9zcGFuPjxzcGFuIGNsYXNzPSJ2YWx1ZSIgaWQ9InNpLXJ4LXNwZWVkIiBzdHlsZT0iY29sb3I6dmFyKC0tc3VjY2VzcykiPi0tPC9zcGFuPjwvc3Bhbj4KCiAgICA8c3BhbiBjbGFzcz0ic2VwIj58PC9zcGFuPgoKICAgIDxzcGFuIGNsYXNzPSJzdGF0LWl0ZW0iPjxzcGFuIGNsYXNzPSJsYWJlbCI+5LiK6KGM6YCf5bqmPC9zcGFuPjxzcGFuIGNsYXNzPSJ2YWx1ZSIgaWQ9InNpLXR4LXNwZWVkIiBzdHlsZT0iY29sb3I6dmFyKC0taW5mbykiPi0tPC9zcGFuPjwvc3Bhbj4KCiAgICA8c3BhbiBjbGFzcz0ic2VwIj58PC9zcGFuPgoKICAgIDxzcGFuIGNsYXNzPSJzdGF0LWl0ZW0iPjxzcGFuIGNsYXNzPSJsYWJlbCI+VENQPC9zcGFuPjxzcGFuIGNsYXNzPSJ2YWx1ZSIgaWQ9InNpLXRjcCIgc3R5bGU9ImNvbG9yOnZhcigtLXdhcm5pbmcpIj4tLTwvc3Bhbj48L3NwYW4+CgogICAgPHNwYW4gY2xhc3M9InNlcCI+fDwvc3Bhbj4KCiAgICA8c3BhbiBjbGFzcz0ic3RhdC1pdGVtIj48c3BhbiBjbGFzcz0ibGFiZWwiPlVEUDwvc3Bhbj48c3BhbiBjbGFzcz0idmFsdWUiIGlkPSJzaS11ZHAiIHN0eWxlPSJjb2xvcjp2YXIoLS13YXJuaW5nKSI+LS08L3NwYW4+PC9zcGFuPgoKICAgIDxzcGFuIGNsYXNzPSJzZXAiPnw8L3NwYW4+CgogICAgPHNwYW4gY2xhc3M9InN0YXQtaXRlbSI+PHNwYW4gY2xhc3M9ImxhYmVsIj7lkK/liqjml7bpl7Q8L3NwYW4+PHNwYW4gY2xhc3M9InZhbHVlIiBpZD0ic2ktaHlzdC1zdGFydCIgc3R5bGU9ImNvbG9yOiNhNzhiZmEiPi0tPC9zcGFuPjwvc3Bhbj4KCjwvZGl2PgoKCgo8IS0tIE1haW4gQXJlYSAtLT4KCjxkaXYgY2xhc3M9Im1haW4iPgoKICAgIDwhLS0gTGVmdCBDb25maWd1cmF0aW9uIFBhbmUgLS0+CgogICAgPGRpdiBjbGFzcz0ibWFpbi1sZWZ0Ij4KCiAgICAgICAgPGRpdiBjbGFzcz0idmlldy1tb2RlLWJhciI+CgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJtb2RlLXRhYnMiPgoKICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9Im1vZGUtdGFiLWJ0biBhY3RpdmUiIGlkPSJ0YWItYnRuLWd1aSIgb25jbGljaz0ic3dpdGNoVmlld01vZGUoJ2d1aScpIj4mIzEyNzkxMjsg5Zu+5b2i5YyW6YWN572uPC9idXR0b24+CgogICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0ibW9kZS10YWItYnRuIiBpZD0idGFiLWJ0bi1yYXciIG9uY2xpY2s9InN3aXRjaFZpZXdNb2RlKCdyYXcnKSI+JiMxMjgyMjE7IOWOn+WniyBZQU1MPC9idXR0b24+CgogICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHgiPgoKICAgICAgICAgICAgICAgIDxzcGFuIGlkPSJjZmctZmlsZS1sYWJlbCI+L2V0Yy9oeXN0ZXJpYS9jb25maWcueWFtbDwvc3Bhbj4KCiAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0ibG9hZEFsbENvbmZpZygpIiB0aXRsZT0i6YeN5paw5Yqg6L29Ij4mIzEyODI2MDsg5Yi35pawPC9idXR0b24+CgogICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgPCEtLSBHVUkgU3VidGFicyAtLT4KCiAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLXN1YnRhYnMiIGlkPSJndWktc3VidGFicyI+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJzdWJ0YWItYnRuIGFjdGl2ZSIgaWQ9InN1YnRhYi1idG4tc2VydmVyIiBvbmNsaWNrPSJzd2l0Y2hTdWJUYWIoJ3NlcnZlcicpIj4mIzEyODIyNTsg5qC45b+D5LiO5pyN5YqhPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJzdWJ0YWItYnRuIiBpZD0ic3VidGFiLWJ0bi1vdXRib3VuZHMiIG9uY2xpY2s9InN3aXRjaFN1YlRhYignb3V0Ym91bmRzJykiPiYjMTI3NzYwOyDlh7rnq5noioLngrkgPHNwYW4gY2xhc3M9InBpbGwtY291bnQiIGlkPSJjb3VudC1vYiI+MDwvc3Bhbj48L2J1dHRvbj4KCiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InN1YnRhYi1idG4iIGlkPSJzdWJ0YWItYnRuLWFjbCIgb25jbGljaz0ic3dpdGNoU3ViVGFiKCdhY2wnKSI+JiMxMjgyNTY7IOWIhua1geinhOWImSA8c3BhbiBjbGFzcz0icGlsbC1jb3VudCIgaWQ9ImNvdW50LWFjbCI+MDwvc3Bhbj48L2J1dHRvbj4KCiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InN1YnRhYi1idG4iIGlkPSJzdWJ0YWItYnRuLXF1aWMiIG9uY2xpY2s9InN3aXRjaFN1YlRhYigncXVpYycpIj4mIzk4ODk7IOaAp+iDveS4jua1geaOpzwvYnV0dG9uPgoKICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic3VidGFiLWJ0biIgaWQ9InN1YnRhYi1idG4td2FycCIgb25jbGljaz0ic3dpdGNoU3ViVGFiKCd3YXJwJykiPiYjMTI4NzM3OyYjNjUwMzk7IFdBUlAg5bel5YW3566xPC9idXR0b24+CgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJzdWJ0YWItYnRuIiBpZD0ic3VidGFiLWJ0bi1leHBvcnQiIG9uY2xpY2s9InN3aXRjaFN1YlRhYignZXhwb3J0JykiPiYjMTI4NjQwOyDoioLngrnliIbkuqvlr7zlh7o8L2J1dHRvbj4KCiAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgPCEtLSBHVUkgQ29udGFpbmVyIC0tPgoKICAgICAgICA8ZGl2IGNsYXNzPSJndWktY29udGFpbmVyIiBpZD0iZ3VpLWNvbnRhaW5lciI+CgogICAgICAgICAgICA8IS0tIFRBQiAxOiBTZXJ2ZXIgJiBDb3JlIC0tPgoKICAgICAgICAgICAgPGRpdiBjbGFzcz0idGFiLXBhbmUgYWN0aXZlIiBpZD0icGFuZS1zZXJ2ZXIiPgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkIj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtaGVhZGVyIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtdGl0bGUiPiYjMTI4MjI1OyDmnI3liqHnm5HlkKzkuI7nvZHnu5w8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1kZXNjIj7phY3nva4gSHlzdGVyaWEgMiDmnI3liqHnm5HlkKznmoQgSVAg5LiOIFVEUCDnq6/lj6M8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncmlkIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+55uR5ZCs5Zyw5Z2A5LiO56uv5Y+jIChMaXN0ZW4pICogPHNtYWxsPuagvOW8jyA656uv5Y+jIOaIliBJUDrnq6/lj6M8L3NtYWxsPjwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iaW5wdXQtd2l0aC1hY3Rpb24iPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgY2xhc3M9ImZvcm0taW5wdXQiIGlkPSJndWktbGlzdGVuIiBwbGFjZWhvbGRlcj0iOjUxMjM1Ij4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLW1pbmkiIG9uY2xpY2s9InNldFByZXNldFBvcnQoNTEyMzUpIj41MTIzNTwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0ic2V0UHJlc2V0UG9ydCg0NDMpIj40NDM8L2J1dHRvbj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLW1pbmkiIG9uY2xpY2s9InNldFByZXNldFBvcnQoODQ0MykiPjg0NDM8L2J1dHRvbj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7ljY/orq7nsbvlnos8L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgdmFsdWU9IlFVSUMgKFVEUCDkvKDovpMpIiBkaXNhYmxlZCBzdHlsZT0ib3BhY2l0eTowLjY7Y3Vyc29yOm5vdC1hbGxvd2VkIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICA8L2Rpdj4KCgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkIj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtaGVhZGVyIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtdGl0bGUiPiYjMTI4MjczOyDorr/pl67orqTor4EgKEF1dGgpPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtZGVzYyI+5a6i5oi356uv6L+e5o6l5pyN5Yqh56uv5omA5L2/55So55qE5a6J5YWo6aqM6K+B5Y+j5LukPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JpZCI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIGZ1bGwiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+6K6k6K+B5a+G56CBIChQYXNzd29yZCkgKjwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iaW5wdXQtd2l0aC1hY3Rpb24iPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgY2xhc3M9ImZvcm0taW5wdXQiIGlkPSJndWktcGFzc3dvcmQiIHR5cGU9InBhc3N3b3JkIiBwbGFjZWhvbGRlcj0i6K+36L6T5YWl6L+e5o6l5a+G56CBIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLW1pbmkiIG9uY2xpY2s9InRvZ2dsZVBhc3NWaXNpYmlsaXR5KCdndWktcGFzc3dvcmQnKSIgdGl0bGU9IuaYvuekui/pmpDol48iPiYjMTI4MDY1OzwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0iZ2VuZXJhdGVSYW5kb21QYXNzKCdndWktcGFzc3dvcmQnKSIgdGl0bGU9IueUn+aIkOW8uumaj+acuuWvhueggSI+JiMxMjc5MjI7IOmaj+acuueUn+aIkDwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0iY29weVZhbHVlKCdndWktcGFzc3dvcmQnKSIgdGl0bGU9IuWkjeWItuWvhueggSI+JiMxMjgyMDM7IOWkjeWItjwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKCgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQiPgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1oZWFkZXIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC10aXRsZSI+JiMxMjgyNzQ7IFRMUyDor4Hkuaborr7nva48L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1kZXNjIj5IeXN0ZXJpYSAyIOW8uuWItuS9v+eUqCBUTFMg5Yqg5a+G5Lyg6L6T77yM5oyH5a6a6K+B5Lmm5LiO56eB6ZKl57ud5a+56Lev5b6EPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JpZCI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZvcm0tbGFiZWwiPuivgeS5puaWh+S7tui3r+W+hCAoY2VydCkgKjwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWlucHV0IiBpZD0iZ3VpLXRscy1jZXJ0IiBwbGFjZWhvbGRlcj0iL2V0Yy9oeXN0ZXJpYS9jZXJ0LmNydCI+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+56eB6ZKl5paH5Lu26Lev5b6EIChrZXkpICo8L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Imd1aS10bHMta2V5IiBwbGFjZWhvbGRlcj0iL2V0Yy9oeXN0ZXJpYS9wcml2YXRlLmtleSI+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAgZnVsbCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj5TTkkg5Lyq6KOF5Z+f5ZCNICjlj6/pgIkpIDxzbWFsbD7oh6rnrb7or4HkuabmiJblpJrln5/lkI3phY3nva7ml7bmjIflrpo8L3NtYWxsPjwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWlucHV0IiBpZD0iZ3VpLXRscy1zbmkiIHBsYWNlaG9sZGVyPSLnlZnnqbrliJnoh6rliqjku47or4Hkuabmj5Dlj5YiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKCgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQiPgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1oZWFkZXIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC10aXRsZSI+JiMxMjc5MTc7IOe9keermeS8quijhSAoTWFzcXVlcmFkZSk8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1kZXNjIj7lvZPmlLbliLDpnZ4gSHlzdGVyaWEg5Y2P6K6u55qEIEhUVFAg5o6i5rWL5pe25Lyq6KOF55qE55uu5qCH6KGM5Li6PC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JpZCI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZvcm0tbGFiZWwiPuS8quijheexu+WeiyAoVHlwZSk8L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzZWxlY3QgY2xhc3M9ImZvcm0tc2VsZWN0IiBpZD0iZ3VpLW1hc3EtdHlwZSI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InByb3h5Ij5wcm94eSAo5Y+N5ZCR5Luj55CG6Iez55uu5qCH572R6aG1KTwvb3B0aW9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJmaWxlIj5maWxlICjmnKzlnLDpnZnmgIHmlofku7bnm67lvZUpPC9vcHRpb24+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IjQwNCI+NDA0ICjnm7TmjqXov5Tlm54gNDA0IE5vdCBGb3VuZCk8L29wdGlvbj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3NlbGVjdD4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7ku6PnkIbnm67moIfnvZHnq5kgKFVSTCk8L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Imd1aS1tYXNxLXVybCIgcGxhY2Vob2xkZXI9IuS+i+WmgjogaHR0cHM6Ly9tYWltYWkuc2VnYS5qcCDmiJYgaHR0cHM6Ly93d3cuYmluZy5jb20iPgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIGZ1bGwiIHN0eWxlPSJmbGV4LWRpcmVjdGlvbjpyb3c7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6MTNweDtmb250LXdlaWdodDo2MDAiPumHjeWGmSBIb3N0IOivt+axguWktCAocmV3cml0ZUhvc3QpPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpIj7lsIblj43ku6Por7fmsYLnmoQgSG9zdCDmm7/mjaLkuLrnm67moIfnvZHlnYDnmoTkuLvmnLrlkI3vvIzmj5Dpq5jkvKroo4XnnJ/lrp7luqY8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9InRvZ2dsZS1zd2l0Y2giPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJndWktbWFzcS1yZXdyaXRlIiBjaGVja2VkPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0idG9nZ2xlLXNsaWRlciI+PC9zcGFuPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZCI+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWhlYWRlciI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLXRpdGxlIj4mIzEyODIwMjsg5rWB6YeP57uf6K6hIEFQSSAoVHJhZmZpY1N0YXRzKTwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWRlc2MiPkh5c3RlcmlhIOWGhee9rueahOi/nuaOpeS4jua1gee7n+iuoeaOpeWPo++8jOS+m+acrOmdouadv+WunuaXtuivu+WPljwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyaWQiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj5BUEkg55uR5ZCs5Zyw5Z2APC9sYWJlbD4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgY2xhc3M9ImZvcm0taW5wdXQiIGlkPSJndWktc3RhdHMtbGlzdGVuIiBwbGFjZWhvbGRlcj0iMTI3LjAuMC4xOjE5OTk5IiB2YWx1ZT0iMTI3LjAuMC4xOjE5OTk5Ij4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj5BUEkg5a+G6ZKlIChTZWNyZXQgVG9rZW4pPC9sYWJlbD4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJpbnB1dC13aXRoLWFjdGlvbiI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Imd1aS1zdGF0cy1zZWNyZXQiIHBsYWNlaG9sZGVyPSI2NOS9jeWNgeWFrei/m+WItuWvhumSpSI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJnZW5lcmF0ZVJhbmRvbVNlY3JldCgnZ3VpLXN0YXRzLXNlY3JldCcpIiB0aXRsZT0i55Sf5oiQ5paw5a+G6ZKlIj4mIzEyNzkyMjsg6ZqP5py6PC9idXR0b24+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8L2Rpdj4KCgoKICAgICAgICAgICAgPCEtLSBUQUIgMjogT3V0Ym91bmRzIC0tPgoKICAgICAgICAgICAgPGRpdiBjbGFzcz0idGFiLXBhbmUiIGlkPSJwYW5lLW91dGJvdW5kcyI+CgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQiPgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1oZWFkZXIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC10aXRsZSI+JiMxMjc3NjA7IOWHuuermeiKgueCueWIl+ihqDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWRlc2MiPumFjee9ruWPr+eUqOS6juWIhua1gei9rOWPkeeahCBTb2NrczUgLyBEaXJlY3Qg5Ye656uZ5pyN5Yqh5ZmoPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJ0ZXN0QWxsT3V0Ym91bmRzKCkiIHRpdGxlPSLmtYvor5XmiYDmnInoioLngrnov57pgJrmgKfkuI7lh7rlj6NJUCI+JiM5ODg5OyDkuIDplK7mtYvor5Xlhajpg6joioLngrk8L2J1dHRvbj4gPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zYXZlIiBvbmNsaWNrPSJvcGVuQWRkT3V0Ym91bmRNb2RhbCgpIj4mIzEwMDEwOyDmt7vliqDlh7rnq5noioLngrk8L2J1dHRvbj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Im91dGJvdW5kLWxpc3QiIGlkPSJvdXRib3VuZC1jYXJkcy1jb250YWluZXIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPCEtLSBSZW5kZXJlZCBieSBKUyAtLT4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8L2Rpdj4KCgoKICAgICAgICAgICAgPCEtLSBUQUIgMzogQUNMIFJ1bGVzIC0tPgoKICAgICAgICAgICAgPGRpdiBjbGFzcz0idGFiLXBhbmUiIGlkPSJwYW5lLWFjbCI+CgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQiPgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1oZWFkZXIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC10aXRsZSI+JiMxMjgyNTY7IEFDTCDliIbmtYHop4TliJk8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1kZXNjIj4mIzk4ODg7JiM2NTAzOTsg6KeE5YiZ55Sx5LiK6Iez5LiL5L6d5bqP5Yy56YWN77yM6aaW5Liq5ZG95Lit55qE6KeE5YiZ55Sf5pWI44CC5Y+v5L2/55SoIOKshiDirIcg6LCD5pW06KeE5YiZ5LyY5YWI57qn44CCPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tc2F2ZSIgb25jbGljaz0ib3BlbkFkZEFjbE1vZGFsKCkiPiYjMTAwMTA7IOa3u+WKoOWIhua1geinhOWImTwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0ib3ZlcmZsb3cteDphdXRvIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDx0YWJsZSBjbGFzcz0iYWNsLXRhYmxlIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8dGhlYWQ+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0cj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT0id2lkdGg6NTBweCI+5bqP5Y+3PC90aD4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT0id2lkdGg6NzBweCI+5LyY5YWI57qnPC90aD4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT0id2lkdGg6MTQwcHgiPuWvvOWQkeWHuuermTwvdGg+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8dGg+5Yy56YWN6KeE5YiZ6KGo6L6+5byPPC90aD4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0aCBzdHlsZT0id2lkdGg6MTAwcHg7dGV4dC1hbGlnbjpyaWdodCI+5pON5L2cPC90aD4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90cj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3RoZWFkPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0Ym9keSBpZD0iYWNsLXRhYmxlLWJvZHkiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8IS0tIFJlbmRlcmVkIGJ5IEpTIC0tPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvdGJvZHk+CgogICAgICAgICAgICAgICAgICAgICAgICA8L3RhYmxlPgoKICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgIDwvZGl2PgoKCgogICAgICAgICAgICA8IS0tIFRBQiA0OiBRVUlDICYgUGVyZm9ybWFuY2UgLS0+CgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUtcXVpYyI+CgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQiPgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1oZWFkZXIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC10aXRsZSI+JiM5ODg5OyBRVUlDIOa1geaOp+eql+WPo+mrmOe6p+iwg+S8mDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWRlc2MiPuiwg+iKguWNlea1geS4juaVtOi/nuaOpeeahOe8k+WGsuWMuuWkp+Wwj++8jOW9seWTjemrmOW7tui/n+OAgeWkp+W4puWuveS4i+eahOWQnuWQkOaAp+iDvTwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjZweCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLW1pbmkiIG9uY2xpY2s9ImFwcGx5UXVpY1ByZXNldCgnZXh0cmVtZScpIj4mIzEyODY0MDsg5p6B6YCf5pa55qGIICgzMk0pPC9idXR0b24+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLW1pbmkiIG9uY2xpY2s9ImFwcGx5UXVpY1ByZXNldCgnYmFsYW5jZWQnKSI+JiM5ODc4OyYjNjUwMzk7IOWdh+ihoeaWueahiCAoMTZNKTwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJhcHBseVF1aWNQcmVzZXQoJ2xpZ2h0JykiPiYjMTI3ODExOyDkvY7lhoXlrZjmlrnmoYggKDhNKTwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyaWQiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7liJ3lp4vmtYHmjqXmlLbnqpflj6MgKGluaXRTdHJlYW1SZWNlaXZlV2luZG93KTwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWlucHV0IiBpZD0iZ3VpLXF1aWMtaW5pdC1zdHJlYW0iIHR5cGU9Im51bWJlciIgcGxhY2Vob2xkZXI9IjE2Nzc3MjE2Ij4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c21hbGwgc3R5bGU9ImNvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2ZvbnQtc2l6ZToxMXB4Ij7pu5jorqQgMTY3NzcyMTYgKDE2IE1CKTwvc21hbGw+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+5pyA5aSn5rWB5o6l5pS256qX5Y+jIChtYXhTdHJlYW1SZWNlaXZlV2luZG93KTwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWlucHV0IiBpZD0iZ3VpLXF1aWMtbWF4LXN0cmVhbSIgdHlwZT0ibnVtYmVyIiBwbGFjZWhvbGRlcj0iMTY3NzcyMTYiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzbWFsbCBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7Zm9udC1zaXplOjExcHgiPum7mOiupCAxNjc3NzIxNiAoMTYgTUIpPC9zbWFsbD4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7liJ3lp4vov57mjqXmjqXmlLbnqpflj6MgKGluaXRDb25uUmVjZWl2ZVdpbmRvdyk8L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Imd1aS1xdWljLWluaXQtY29ubiIgdHlwZT0ibnVtYmVyIiBwbGFjZWhvbGRlcj0iMzM1NTQ0MzIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzbWFsbCBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7Zm9udC1zaXplOjExcHgiPum7mOiupCAzMzU1NDQzMiAoMzIgTUIpPC9zbWFsbD4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGNsYXNzPSJmb3JtLWxhYmVsIj7mnIDlpKfov57mjqXmjqXmlLbnqpflj6MgKG1heENvbm5SZWNlaXZlV2luZG93KTwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWlucHV0IiBpZD0iZ3VpLXF1aWMtbWF4LWNvbm4iIHR5cGU9Im51bWJlciIgcGxhY2Vob2xkZXI9IjMzNTU0NDMyIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c21hbGwgc3R5bGU9ImNvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2ZvbnQtc2l6ZToxMXB4Ij7pu5jorqQgMzM1NTQ0MzIgKDMyIE1CKTwvc21hbGw+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZCI+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWhlYWRlciI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLXRpdGxlIj4mIzEyODM5MTsg5bim5a695o6n5Yi2IChCYW5kd2lkdGgpPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtZGVzYyI+5pyN5Yqh56uv6ZmQ6YCf6YCJ6aG544CC55WZ56m66KGo56S65peg6ZmQ5Yi277yM5YWF5YiG5Yip55SoIEJCUiDmi6XloZ7mjqfliLbjgII8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncmlkIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+5LiK6KGM6ZmQ6YCfIChVcGxvYWQpIDxzbWFsbD7kvovlpoI6IDEwMCBtYnBzPC9zbWFsbD48L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxpbnB1dCBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9Imd1aS1idy11cCIgcGxhY2Vob2xkZXI9IueVmeepuuS4jemZkOWItiI+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxsYWJlbCBjbGFzcz0iZm9ybS1sYWJlbCI+5LiL6KGM6ZmQ6YCfIChEb3dubG9hZCkgPHNtYWxsPuS+i+WmgjogMjAwIG1icHM8L3NtYWxsPjwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWlucHV0IiBpZD0iZ3VpLWJ3LWRvd24iIHBsYWNlaG9sZGVyPSLnlZnnqbrkuI3pmZDliLYiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIGZ1bGwiIHN0eWxlPSJmbGV4LWRpcmVjdGlvbjpyb3c7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6MTNweDtmb250LXdlaWdodDo2MDAiPuW/veeVpeWuouaIt+err+WjsOaYjueahOW4puWuvSAoaWdub3JlQ2xpZW50QmFuZHdpZHRoKTwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10ZXh0LW11dGVkKSI+5byA5ZCv5ZCO5peg6KeG5a6i5oi356uv5LiK5oql5rWL6YCf77yM5by65Yi25oyJ5pyN5Yqh56uvIEJCUiDliqjmgIHmi6XloZ7mjqfliLblj5HpgIHmlbDmja48L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9InRvZ2dsZS1zd2l0Y2giPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJndWktYnctaWdub3JlIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gY2xhc3M9InRvZ2dsZS1zbGlkZXIiPjwvc3Bhbj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2xhYmVsPgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgICAgIAoKICAgICAgICAgICAgPCEtLSBUQUIgNjogV0FSUCBUb29sIC0tPgoKICAgICAgICAgICAgPGRpdiBjbGFzcz0idGFiLXBhbmUiIGlkPSJwYW5lLXdhcnAiPgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkIj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtaGVhZGVyIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtdGl0bGUiPiYjMTI4NzM3OyYjNjUwMzk7IENsb3VkZmxhcmUgV0FSUCDmoLjlv4PnirbmgIE8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1kZXNjIj7lhoXnva7ni6znq4vovbvph48gV0FSUCDlrqLmiLfnq6/vvIzmnKzlnLDnm5HlkKwgU29ja3M1IOerr+WPoyAxMjcuMC4wLjE6NDAwMDDvvIzkuI3lvbHlk40gVlBTIOWOn+eUn+e9keWNoeS4jiBTU0gg6L+e5o6lPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6NnB4Ij4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0iY2hlY2tXYXJwU3RhdHVzKHRydWUpIj4mIzk4ODk7IOaOoua1iyBXQVJQIOWHuuWPozwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJjb250cm9sV2FycCgncmVzdGFydCcpIj4mIzg2MzU7IOmHjeWQr+acjeWKoTwvYnV0dG9uPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJjb250cm9sV2FycCgncmVfcmVnaXN0ZXInKSI+JiMxMjc5MjI7IOiOt+WPluWFqOaWsOi0puWPt+S4jklQPC9idXR0b24+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9IndhcnAtc3RhdHVzLWJveCI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4Ij4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6MTNweDtmb250LXdlaWdodDo2MDAiPuacjeWKoeeKtuaAgTo8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0iYmFkZ2Utc3RhdHVzIiBpZD0id2FycC1zZXJ2aWNlLWJhZGdlIj48c3BhbiBjbGFzcz0iZG90LXB1bHNlIj48L3NwYW4+IDxzcGFuIGlkPSJ3YXJwLXNlcnZpY2UtdGV4dCI+5qOA5rWL5LitLi4uPC9zcGFuPjwvc3Bhbj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT0iZm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCkiPnwg56uv5Y+jOiA8Yj5Tb2NrczUgMTI3LjAuMC4xOjQwMDAwPC9iPjwvc3Bhbj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4Ij4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c3BhbiBzdHlsZT0iZm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCkiPkh5MiDliIbmtYHnirbmgIE6PC9zcGFuPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzcGFuIGlkPSJ3YXJwLWh5Mi1zdGF0dXMtYmFkZ2UiIGNsYXNzPSJiYWRnZS1zdGF0dXMgc3RvcHBlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4Ij7mnKrmjqXlhaU8L3NwYW4+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9IndhcnAtaXAtYm94IiBpZD0id2FycC10cmFjZS1ib3giPgoKICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gaWQ9IndhcnAtdHJhY2UtaW5mbyI+JiM5MjAzOyDngrnlh7vkuIrmlrnjgIzmjqLmtYsgV0FSUCDlh7rlj6PjgI3ojrflj5blvZPliY0gV0FSUCDlh7rnq5kgSVAg5LiO5Zyw5Yy6Li4uPC9zcGFuPgoKICAgICAgICAgICAgICAgICAgICAgICAgPHNwYW4gaWQ9IndhcnAtdHJhY2UtdGFnIj48L3NwYW4+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKCgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQiPgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1oZWFkZXIiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC10aXRsZSI+JiM5ODg5OyDkuIDplK7otbAgV0FSUCDmjqfliLbkuK3lv4M8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1kZXNjIj7oh6rliqjlsIYgV0FSUCDliqDlhaUgSHlzdGVyaWEgMiDlh7rnq5nlubbphY3nva4gQUNMIOWIhua1ge+8jOS4gOmUruS/neWtmOW5tuW5s+a7kemHjeWQr+eUn+aViDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpdCxtaW5tYXgoMjYwcHgsMWZyKSk7Z2FwOjEycHgiPgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1iZy1zdWJjYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czo4cHg7cGFkZGluZzoxNHB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEwcHgiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxNHB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjojZmZmIj4mIzEyODY0MDsg5LiA6ZSu5YWo5bGA6LWwIFdBUlA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10ZXh0LW11dGVkKSI+5bCGIEh5c3RlcmlhIDIg5YWo6YeP5Luj55CG5rWB6YeP57uP55SxIENsb3VkZmxhcmUgV0FSUCDlubLlh4DkvY/lroUv5ZWG5LiaIElQIOWHuuerme+8jOWFqOmdoumakOiXjyBWUFMg55yf5a6eIElQPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zYXZlIiBzdHlsZT0ibWFyZ2luLXRvcDphdXRvIiBvbmNsaWNrPSJ0b2dnbGVIeTJXYXJwKCdnbG9iYWwnKSI+JiMxMjg2NDA7IOeri+WNs+WQr+eUqOWFqOWxgOi1sCBXQVJQPC9idXR0b24+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tYmctc3ViY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6OHB4O3BhZGRpbmc6MTRweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDoxMHB4Ij4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6MTRweDtmb250LXdlaWdodDo3MDA7Y29sb3I6I2ZmZiI+JiMxMjc5MTY7IOS4gOmUrua1geWqkuS9kyAvIEFJIOino+mUgTwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpIj7ku4Xpkojlr7kgT3BlbkFJIChDaGF0R1BUKeOAgU5ldGZsaXjjgIFEaXNuZXkr44CBQ2xhdWRlIOetieWPl+mZkOe9keermei1sCBXQVJQ77yM5YW25LuW6K6/6Zeu5L+d5oyB55u06L+e5oiW5Y6f5pyJ5Ye656uZPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zdGFydCIgc3R5bGU9Im1hcmdpbi10b3A6YXV0byIgb25jbGljaz0idG9nZ2xlSHkyV2FycCgndW5sb2NrJykiPiYjMTI3OTE2OyDnq4vljbPlkK/nlKjmmbrog73op6PplIHliIbmtYE8L2J1dHRvbj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1iZy1zdWJjYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czo4cHg7cGFkZGluZzoxNHB4O2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEwcHgiPgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxNHB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjojZmZmIj4mIzEwMDA2OyDlhbPpl60gV0FSUCDliIbmtYE8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10ZXh0LW11dGVkKSI+56e76ZmkIEFDTCDop4TliJnkuK3nmoQgV0FSUCDliIbmtYHvvIzmgaLlpI3ljp/mnKznmoTnm7Tov57kuI7lhbbku5bku6PnkIboioLngrnliIbmtYHorr7nva48L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi11cGRhdGUiIG9uY2xpY2s9InVwZGF0ZUh5MigpIiB0aXRsZT0i5Y2H57qnIEh5c3RlcmlhIDIg5qC45b+D5Yiw5pyA5paw54mI5pysIj4KICAgICAgICAgICAgICAgIDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiB3aWR0aD0iMTQiIGhlaWdodD0iMTQiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lkdGg9IjIiIGZpbGw9Im5vbmUiPjxwYXRoIGQ9Ik00IDE2djFhMyAzIDAgMCAwIDMgM2gxMGEzIDMgMCAwIDAgMy0zdi0xTTE2IDEwbC00IDQtNC00TTEyIDR2MTAiLz48L3N2Zz4KICAgICAgICAgICAgICAgIOabtOaWsOaguOW/gwogICAgICAgICAgICA8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1sb2dvdXQiIHN0eWxlPSJtYXJnaW4tdG9wOmF1dG8iIG9uY2xpY2s9InRvZ2dsZUh5MldhcnAoJ2Rpc2FibGUnKSI+JiMxMDAwNjsg5oGi5aSN6buY6K6k5YiG5rWBPC9idXR0b24+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8L2Rpdj4KCgoKICAgICAgICAgICAgPCEtLSBUQUIgNTogQ2xpZW50IEV4cG9ydCAtLT4KCiAgICAgICAgICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFuZS1leHBvcnQiPgoKICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkIj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtaGVhZGVyIj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxkaXY+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZ3VpLWNhcmQtdGl0bGUiPiYjMTI4NjQwOyBIeXN0ZXJpYSAyIOWuouaIt+err+iuoumYhemTvuaOpTwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWRlc2MiPumAmueUqOWIhuS6q+mTvuaOpe+8jOaUr+aMgSB2MnJheU7jgIFOZWtvcmF544CBQ2xhc2ggVmVyZ2XjgIFTaGFkb3dyb2NrZXTjgIFTaW5nLWJveCDnrYnkuLvmtYHlrqLmiLfnq6/nm7TmjqXlr7zlhaU8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgogICAgICAgICAgICAgICAgICAgICAgICA8bGFiZWwgY2xhc3M9ImZvcm0tbGFiZWwiPuagh+WHhuWIhuS6q+mTvuaOpSAoaHlzdGVyaWEyOi8vKTwvbGFiZWw+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJpbnB1dC13aXRoLWFjdGlvbiI+CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWlucHV0IiBpZD0iZXhwb3J0LXVyaSIgcmVhZG9ubHkgc3R5bGU9ImZvbnQtZmFtaWx5Om1vbm9zcGFjZTtiYWNrZ3JvdW5kOnZhcigtLWJnLW1haW4pIj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNhdmUiIG9uY2xpY2s9ImNvcHlWYWx1ZSgnZXhwb3J0LXVyaScpIj4mIzEyODIwMzsg5LiA6ZSu5aSN5Yi26ZO+5o6lPC9idXR0b24+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZCI+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWhlYWRlciI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLXRpdGxlIj4mIzEyODIyMDsgQ2xhc2ggTWV0YSAoTWlob21vKSDoioLngrnphY3nva48L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZC1kZXNjIj7lj6/nm7TmjqXnspjotLTov5sgQ2xhc2ggTWV0YSDphY3nva7mlofku7bnmoQgcHJveGllczog5YiX6KGo5LitPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJjb3B5VmFsdWUoJ2V4cG9ydC1jbGFzaCcpIj4mIzEyODIwMzsg5aSN5Yi26YWN572uPC9idXR0b24+CgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgICAgICAgICA8dGV4dGFyZWEgY2xhc3M9ImZvcm0taW5wdXQiIGlkPSJleHBvcnQtY2xhc2giIHJlYWRvbmx5IHN0eWxlPSJmb250LWZhbWlseTptb25vc3BhY2U7aGVpZ2h0OjEyMHB4O3Jlc2l6ZTpub25lO2JhY2tncm91bmQ6dmFyKC0tYmctbWFpbikiPjwvdGV4dGFyZWE+CgogICAgICAgICAgICAgICAgPC9kaXY+CgoKCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJndWktY2FyZCI+CgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWhlYWRlciI+CgogICAgICAgICAgICAgICAgICAgICAgICA8ZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLXRpdGxlIj4mIzEyODIyMDsgU2luZy1ib3gg5Ye656uZ6YWN572uIChPdXRib3VuZCBKU09OKTwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Imd1aS1jYXJkLWRlc2MiPuWPr+ebtOaOpeeymOi0tOi/myBTaW5nLWJveCDnmoQgb3V0Ym91bmRzIOaVsOe7hOS4rTwvZGl2PgoKICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0iY29weVZhbHVlKCdleHBvcnQtc2luZ2JveCcpIj4mIzEyODIwMzsg5aSN5Yi2IEpTT048L2J1dHRvbj4KCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICAgICAgICAgIDx0ZXh0YXJlYSBjbGFzcz0iZm9ybS1pbnB1dCIgaWQ9ImV4cG9ydC1zaW5nYm94IiByZWFkb25seSBzdHlsZT0iZm9udC1mYW1pbHk6bW9ub3NwYWNlO2hlaWdodDoxNDBweDtyZXNpemU6bm9uZTtiYWNrZ3JvdW5kOnZhcigtLWJnLW1haW4pIj48L3RleHRhcmVhPgoKICAgICAgICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgICAgPC9kaXY+CgogICAgICAgIDwvZGl2PgoKCgogICAgICAgIDwhLS0gUmF3IFlBTUwgUGFuZSAtLT4KCiAgICAgICAgPGRpdiBpZD0icmF3LXBhbmUiPgoKICAgICAgICAgICAgPGRpdiBzdHlsZT0icGFkZGluZzo2cHggMnB4IDEwcHg7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbiI+CgogICAgICAgICAgICAgICAgPHNwYW4gc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpIj7nm7TmjqXkv67mlLnljp/lp4sgWUFNTCDmlofmnKzmlofku7bjgILkv53lrZjml7bkvJroh6rliqjlpIfku73ljp/phY3nva7lubbmoKHpqozor63ms5XjgII8L3NwYW4+CgogICAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo2cHgiPgoKICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0ic3luY0d1aVRvUmF3WWFtbCgpIj4mIzg2MzU7IOS7juWbvuW9oumFjee9ruabtOaWsOiHsyBZQU1MPC9idXR0b24+CgogICAgICAgICAgICAgICAgPC9kaXY+CgogICAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICAgIDx0ZXh0YXJlYSBpZD0iY29uZmlnLWVkaXRvciIgc3BlbGxjaGVjaz0iZmFsc2UiPjwvdGV4dGFyZWE+CgogICAgICAgIDwvZGl2PgoKICAgIDwvZGl2PgoKCgogICAgPCEtLSBEcmFnZ2FibGUgRGl2aWRlciAtLT4KCiAgICA8ZGl2IGNsYXNzPSJkaXZpZGVyIiBpZD0iZGl2aWRlciI+PC9kaXY+CgoKCiAgICA8IS0tIFJpZ2h0IExvZ3MgJiBNb25pdG9yaW5nIFBhbmUgLS0+CgogICAgPGRpdiBjbGFzcz0ibWFpbi1yaWdodCI+CgogICAgICAgIDxkaXYgY2xhc3M9ImxvZy1iYXIiPgoKICAgICAgICAgICAgPHNwYW4+CgogICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biBhY3RpdmUiIGlkPSJ0YWItYnRuLWxvZyIgb25jbGljaz0ic3dpdGNoTW9uaXRvclRhYignbG9nJykiPiYjMTI4MjAzOyDlrp7ml7bml6Xlv5c8L2J1dHRvbj4KCiAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWJ0bi1jb25uIiBvbmNsaWNrPSJzd2l0Y2hNb25pdG9yVGFiKCdjb25uJykiPiYjMTI4Mjc5OyDov57mjqXkuI7mtYHnm5Hmjqc8L2J1dHRvbj4KCiAgICAgICAgICAgIDwvc3Bhbj4KCiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJsb2ctY29udHJvbHMiIGlkPSJsb2ctY29udHJvbHMiPgoKICAgICAgICAgICAgICAgIDxzcGFuIGlkPSJsb2ctbGluZS1jb3VudCIgc3R5bGU9ImNvbG9yOnZhcigtLXRleHQtbXV0ZWQpO2ZvbnQtc2l6ZToxMXB4Ij4wIGxpbmVzPC9zcGFuPgoKICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJsb2FkTG9ncygpO2lmKCFsb2dBdXRvUmVmcmVzaCl0b2dnbGVBdXRvUmVmcmVzaCgpOyIgdGl0bGU9Iueri+WNs+WIt+aWsCI+JiMxMjgyNjA7PC9idXR0b24+CgogICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLW1pbmkiIG9uY2xpY2s9ImNsZWFyTG9ncygpIiB0aXRsZT0i5riF5bGPIj4mIzEyODQ2NTsmIzY1MDM5OzwvYnV0dG9uPgoKICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBpZD0ibG9nLWF1dG8tYnRuIiBvbmNsaWNrPSJ0b2dnbGVBdXRvUmVmcmVzaCgpIiB0aXRsZT0i6Ieq5Yqo5Yi35pawIj4mIzkyMDg7JiM2NTAzOTs8L2J1dHRvbj4KCiAgICAgICAgICAgIDwvc3Bhbj4KCiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJsb2ctY29udHJvbHMiIGlkPSJjb25uLWNvbnRyb2xzIiBzdHlsZT0iZGlzcGxheTpub25lIj4KCiAgICAgICAgICAgICAgICA8c3BhbiBpZD0iY29ubi11cGRhdGVkIiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7Zm9udC1zaXplOjExcHgiPjwvc3Bhbj4KCiAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0ibG9hZFN0cmVhbXMoKSIgdGl0bGU9IuWIt+aWsCI+JiMxMjgyNjA7PC9idXR0b24+CgogICAgICAgICAgICA8L3NwYW4+CgogICAgICAgIDwvZGl2PgoKICAgICAgICA8ZGl2IGlkPSJsb2ctY29udGVudCI+PC9kaXY+CgogICAgICAgIDxkaXYgaWQ9ImNvbm4tY29udGVudCIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+PC9kaXY+CgogICAgPC9kaXY+Cgo8L2Rpdj4KCgoKPHNjcmlwdD4KCgoKLy8gLS0tLS0tLS0tLSDkuLvpopjnrqHnkIYgKOa3seiJsiAvIOa1heiJsiAvIOi3n+maj+ezu+e7nykgLS0tLS0tLS0tLQoKZnVuY3Rpb24gYXBwbHlUaGVtZSh0aGVtZSl7CgogICAgdmFyIGlzRGFyayA9IHRydWU7CgogICAgaWYodGhlbWUgPT09ICdsaWdodCcpewoKICAgICAgICBpc0RhcmsgPSBmYWxzZTsKCiAgICB9IGVsc2UgaWYodGhlbWUgPT09ICdkYXJrJyl7CgogICAgICAgIGlzRGFyayA9IHRydWU7CgogICAgfSBlbHNlIHsKCiAgICAgICAgaXNEYXJrID0gISh3aW5kb3cubWF0Y2hNZWRpYSAmJiB3aW5kb3cubWF0Y2hNZWRpYSgnKHByZWZlcnMtY29sb3Itc2NoZW1lOiBsaWdodCknKS5tYXRjaGVzKTsKCiAgICB9CgogICAgZG9jdW1lbnQuYm9keS5jbGFzc0xpc3QudG9nZ2xlKCd0aGVtZS1saWdodCcsICFpc0RhcmspOwoKICAgIFsnZGFyaycsJ2xpZ2h0JywnYXV0byddLmZvckVhY2goZnVuY3Rpb24odCl7CgogICAgICAgIHZhciBiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RoZW1lLWJ0bi0nICsgdCk7CgogICAgICAgIGlmKGIpIGIuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgdCA9PT0gdGhlbWUpOwoKICAgIH0pOwoKfQoKZnVuY3Rpb24gc2V0VGhlbWUodGhlbWUpewoKICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdoeTJfdGhlbWUnLCB0aGVtZSk7CgogICAgYXBwbHlUaGVtZSh0aGVtZSk7Cgp9Cgp2YXIgY3VycmVudFRoZW1lID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ2h5Ml90aGVtZScpIHx8ICdhdXRvJzsKCmFwcGx5VGhlbWUoY3VycmVudFRoZW1lKTsKCmlmKHdpbmRvdy5tYXRjaE1lZGlhKXsKCiAgICB3aW5kb3cubWF0Y2hNZWRpYSgnKHByZWZlcnMtY29sb3Itc2NoZW1lOiBsaWdodCknKS5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCBmdW5jdGlvbigpewoKICAgICAgICBpZihsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnaHkyX3RoZW1lJykgPT09ICdhdXRvJyB8fCAhbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ2h5Ml90aGVtZScpKXsKCiAgICAgICAgICAgIGFwcGx5VGhlbWUoJ2F1dG8nKTsKCiAgICAgICAgfQoKICAgIH0pOwoKfQoKCgoKCi8vIC0tLS0tLS0tLS0g5Ye656uZ6IqC54K56L+e6YCa5oCn5LiO5Ye65Y+jIElQIOa1i+ivlSAtLS0tLS0tLS0tCgpmdW5jdGlvbiB0ZXN0T3V0Ym91bmROb2RlKGlkeCwgYnRuKXsKCiAgICB2YXIgb2IgPSBjdXJyZW50Q29uZmlnLm91dGJvdW5kc1tpZHhdOwoKICAgIGlmKCFvYikgcmV0dXJuOwoKICAgIHZhciByZXNCb3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnb2ItdGVzdC0nICsgaWR4KTsKCiAgICBpZihidG4pewoKICAgICAgICBidG4udGV4dENvbnRlbnQgPSAn4o+zIOa1i+ivleS4rS4uLic7CgogICAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CgogICAgfQoKICAgIGlmKHJlc0JveCkgcmVzQm94LmlubmVySFRNTCA9ICc8c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tdGV4dC1tdXRlZCk7Zm9udC1zaXplOjExcHgiPuato+WcqOaOoua1i+WHuuWPoyBJUCDkuI7lu7bov58uLi48L3NwYW4+JzsKCiAgICAKCiAgICBmZXRjaCgnL2FwaS9vdXRib3VuZC90ZXN0JywgewoKICAgICAgICBtZXRob2Q6ICdQT1NUJywKCiAgICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbid9LAoKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShvYikKCiAgICB9KS50aGVuKHI9PnIuanNvbigpKS50aGVuKGQ9PnsKCiAgICAgICAgaWYoYnRuKXsKCiAgICAgICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfimqEg5rWL6K+VJzsKCiAgICAgICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwoKICAgICAgICB9CgogICAgICAgIGlmKCFyZXNCb3gpIHJldHVybjsKCiAgICAgICAgaWYoZC5zdWNjZXNzKXsKCiAgICAgICAgICAgIHZhciB3YXJwQmFkZ2UgPSAoZC53YXJwID09PSAnb24nKSA/ICcgPHNwYW4gY2xhc3M9IndhcnAtdGFnIj5XQVJQPC9zcGFuPicgOiAnJzsKCiAgICAgICAgICAgIHZhciBsb2NTdHIgPSBkLmxvYyA/ICgnICgnICsgZC5sb2MgKyAoZC5jb2xvID8gJyDCtyAnICsgZC5jb2xvIDogJycpICsgJyknKSA6ICcnOwoKICAgICAgICAgICAgcmVzQm94LmlubmVySFRNTCA9ICc8c3BhbiBjbGFzcz0ib2ItdGVzdC1iYWRnZSBvayI+PHNwYW4gc3R5bGU9ImNvbG9yOnZhcigtLXN1Y2Nlc3MpIj7il488L3NwYW4+ICcgKwoKICAgICAgICAgICAgICAgIGVzY2FwZUh0bWwoZC5pcCkgKyBsb2NTdHIgKyAnIMK3ICcgKyBkLmRlbGF5ICsgJ21zJyArIHdhcnBCYWRnZSArICc8L3NwYW4+JzsKCiAgICAgICAgfSBlbHNlIHsKCiAgICAgICAgICAgIHJlc0JveC5pbm5lckhUTUwgPSAnPHNwYW4gY2xhc3M9Im9iLXRlc3QtYmFkZ2UgZXJyIj48c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tZGFuZ2VyKSI+4pePPC9zcGFuPiAnICsKCiAgICAgICAgICAgICAgICBlc2NhcGVIdG1sKGQuZXJyb3IgfHwgJ+i/nuaOpei2heaXticpICsgJzwvc3Bhbj4nOwoKICAgICAgICB9CgogICAgfSkuY2F0Y2goZnVuY3Rpb24oZSl7CgogICAgICAgIGlmKGJ0bil7IGJ0bi50ZXh0Q29udGVudCA9ICfimqEg5rWL6K+VJzsgYnRuLmRpc2FibGVkID0gZmFsc2U7IH0KCiAgICAgICAgaWYocmVzQm94KSByZXNCb3guaW5uZXJIVE1MID0gJzxzcGFuIGNsYXNzPSJvYi10ZXN0LWJhZGdlIGVyciI+4pePIOa1i+ivleivt+axguWksei0pTwvc3Bhbj4nOwoKICAgIH0pOwoKfQoKCgpmdW5jdGlvbiB0ZXN0QWxsT3V0Ym91bmRzKCl7CgogICAgdmFyIGxpc3QgPSAoY3VycmVudENvbmZpZyAmJiBjdXJyZW50Q29uZmlnLm91dGJvdW5kcykgfHwgW107CgogICAgaWYobGlzdC5sZW5ndGggPT09IDApewoKICAgICAgICBzaG93QWxlcnQoJ+aaguaXoOWHuuermeiKgueCueWPr+a1i+ivlScsICdpbmZvJyk7CgogICAgICAgIHJldHVybjsKCiAgICB9CgogICAgc2hvd0FsZXJ0KCfmraPlnKjkvp3mrKHmtYvor5Xlhajpg6ggJyArIGxpc3QubGVuZ3RoICsgJyDkuKrlh7rnq5noioLngrkuLi4nLCAnaW5mbycpOwoKICAgIHZhciBpID0gMDsKCiAgICBmdW5jdGlvbiBuZXh0KCl7CgogICAgICAgIGlmKGkgPj0gbGlzdC5sZW5ndGgpewoKICAgICAgICAgICAgc2hvd0FsZXJ0KCflhajpg6joioLngrnmtYvor5XlrozmiJDvvIEnLCAnb2snKTsKCiAgICAgICAgICAgIHJldHVybjsKCiAgICAgICAgfQoKICAgICAgICB2YXIgY3VySWR4ID0gaTsKCiAgICAgICAgdmFyIGJ0biA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJyNvYi1jYXJkLScgKyBjdXJJZHggKyAnIC5idG4tdGVzdC1vYicpOwoKICAgICAgICB0ZXN0T3V0Ym91bmROb2RlKGN1cklkeCwgYnRuKTsKCiAgICAgICAgaSsrOwoKICAgICAgICBzZXRUaW1lb3V0KG5leHQsIDQwMCk7CgogICAgfQoKICAgIG5leHQoKTsKCn0KCgoKLy8gLS0tLS0tLS0tLSBXQVJQIOW3peWFt+euseeKtuaAgeS4juaOp+WItiAtLS0tLS0tLS0tCgpmdW5jdGlvbiBjaGVja1dhcnBTdGF0dXMobWFudWFsKXsKCiAgICBpZihtYW51YWwpIHNob3dBbGVydCgn5q2j5Zyo5o6i5rWLIFdBUlAg5Ye656uZ54q25oCB5LiO5Ye65Y+jIElQLi4uJywgJ2luZm8nKTsKCiAgICBmZXRjaCgnL2FwaS93YXJwL3N0YXR1cycpLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oZD0+ewoKICAgICAgICB2YXIgc0JhZGdlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3dhcnAtc2VydmljZS1iYWRnZScpOwoKICAgICAgICB2YXIgc1R4dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd3YXJwLXNlcnZpY2UtdGV4dCcpOwoKICAgICAgICB2YXIgaEJhZGdlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3dhcnAtaHkyLXN0YXR1cy1iYWRnZScpOwoKICAgICAgICB2YXIgdEluZm8gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnd2FycC10cmFjZS1pbmZvJyk7CgogICAgICAgIHZhciB0VGFnID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3dhcnAtdHJhY2UtdGFnJyk7CgogICAgICAgIAoKICAgICAgICBpZihzQmFkZ2UgJiYgc1R4dCl7CgogICAgICAgICAgICBpZihkLnJ1bm5pbmcpewoKICAgICAgICAgICAgICAgIHNCYWRnZS5jbGFzc05hbWUgPSAnYmFkZ2Utc3RhdHVzJzsKCiAgICAgICAgICAgICAgICBzVHh0LnRleHRDb250ZW50ID0gJ+i/kOihjOS4rSc7CgogICAgICAgICAgICB9IGVsc2UgewoKICAgICAgICAgICAgICAgIHNCYWRnZS5jbGFzc05hbWUgPSAnYmFkZ2Utc3RhdHVzIHN0b3BwZWQnOwoKICAgICAgICAgICAgICAgIHNUeHQudGV4dENvbnRlbnQgPSAn5bey5YGc5q2iJzsKCiAgICAgICAgICAgIH0KCiAgICAgICAgfQoKICAgICAgICAKCiAgICAgICAgaWYoaEJhZGdlKXsKCiAgICAgICAgICAgIGlmKGQuaHkyX3dhcnBfZ2xvYmFsKXsKCiAgICAgICAgICAgICAgICBoQmFkZ2UuY2xhc3NOYW1lID0gJ2JhZGdlLXN0YXR1cyc7CgogICAgICAgICAgICAgICAgaEJhZGdlLnN0eWxlLmNvbG9yID0gJyMzOGJkZjgnOwoKICAgICAgICAgICAgICAgIGhCYWRnZS5zdHlsZS5ib3JkZXJDb2xvciA9ICdyZ2JhKDU2LDE4OSwyNDgsMC40KSc7CgogICAgICAgICAgICAgICAgaEJhZGdlLnN0eWxlLmJhY2tncm91bmQgPSAncmdiYSg1NiwxODksMjQ4LDAuMTUpJzsKCiAgICAgICAgICAgICAgICBoQmFkZ2UudGV4dENvbnRlbnQgPSAn8J+agCDlhajlsYDotbAgV0FSUCc7CgogICAgICAgICAgICB9IGVsc2UgaWYoZC5oeTJfaGFzX3dhcnApewoKICAgICAgICAgICAgICAgIGhCYWRnZS5jbGFzc05hbWUgPSAnYmFkZ2Utc3RhdHVzJzsKCiAgICAgICAgICAgICAgICBoQmFkZ2Uuc3R5bGUuY29sb3IgPSAnI2E3OGJmYSc7CgogICAgICAgICAgICAgICAgaEJhZGdlLnN0eWxlLmJvcmRlckNvbG9yID0gJ3JnYmEoMTY3LDEzOSwyNTAsMC40KSc7CgogICAgICAgICAgICAgICAgaEJhZGdlLnN0eWxlLmJhY2tncm91bmQgPSAncmdiYSgxNjcsMTM5LDI1MCwwLjE1KSc7CgogICAgICAgICAgICAgICAgaEJhZGdlLnRleHRDb250ZW50ID0gJ/Cfjqwg6Kej6ZSB5YiG5rWB6LWwIFdBUlAnOwoKICAgICAgICAgICAgfSBlbHNlIHsKCiAgICAgICAgICAgICAgICBoQmFkZ2UuY2xhc3NOYW1lID0gJ2JhZGdlLXN0YXR1cyBzdG9wcGVkJzsKCiAgICAgICAgICAgICAgICBoQmFkZ2UudGV4dENvbnRlbnQgPSAn5pyq5o6l5YWlIEh5MiDliIbmtYEnOwoKICAgICAgICAgICAgfQoKICAgICAgICB9CgogICAgICAgIAoKICAgICAgICBpZih0SW5mbyAmJiB0VGFnKXsKCiAgICAgICAgICAgIGlmKGQudHJhY2UgJiYgZC50cmFjZS5zdWNjZXNzKXsKCiAgICAgICAgICAgICAgICB2YXIgbG9jID0gZC50cmFjZS5sb2MgPyAoJyDCtyDlnLDljLo6ICcgKyBkLnRyYWNlLmxvYyArICcgKCcgKyBkLnRyYWNlLmNvbG8gKyAnKScpIDogJyc7CgogICAgICAgICAgICAgICAgdEluZm8uaW5uZXJIVE1MID0gJzxiIHN0eWxlPSJjb2xvcjp2YXIoLS1zdWNjZXNzKSI+V0FSUCDlh7rnq5kgSVA6ICcgKyBlc2NhcGVIdG1sKGQudHJhY2UuaXApICsgJzwvYj4nICsgbG9jICsgJyDCtyDlu7bov58gJyArIGQudHJhY2UuZGVsYXkgKyAnbXMnOwoKICAgICAgICAgICAgICAgIHRUYWcuaW5uZXJIVE1MID0gJzxzcGFuIGNsYXNzPSJ3YXJwLXRhZyI+V0FSUCBPTjwvc3Bhbj4nOwoKICAgICAgICAgICAgICAgIGlmKG1hbnVhbCkgc2hvd0FsZXJ0KCdXQVJQIOWHuuermeaOoua1i+aIkOWKn++8geWHuuWPoyBJUDogJyArIGQudHJhY2UuaXAsICdvaycpOwoKICAgICAgICAgICAgfSBlbHNlIHsKCiAgICAgICAgICAgICAgICB0SW5mby50ZXh0Q29udGVudCA9ICfml6Dms5XpgJrov4cgV0FSUCAoMTI3LjAuMC4xOjQwMDAwKSDorr/pl67lpJbpg6jnvZHnu5w6ICcgKyAoKGQudHJhY2UgJiYgZC50cmFjZS5lcnJvcikgfHwgJ+i/nuaOpeWksei0pScpOwoKICAgICAgICAgICAgICAgIHRUYWcuaW5uZXJIVE1MID0gJyc7CgogICAgICAgICAgICAgICAgaWYobWFudWFsKSBzaG93QWxlcnQoJ1dBUlAg5o6i5rWL5aSx6LSlOiAnICsgKChkLnRyYWNlICYmIGQudHJhY2UuZXJyb3IpIHx8ICfmnKrlk43lupQnKSwgJ2VycicpOwoKICAgICAgICAgICAgfQoKICAgICAgICB9CgogICAgfSkuY2F0Y2goZnVuY3Rpb24oZSl7CgogICAgICAgIGlmKG1hbnVhbCkgc2hvd0FsZXJ0KCfor7fmsYLlpLHotKU6ICcgKyBlLCAnZXJyJyk7CgogICAgfSk7Cgp9CgoKCmZ1bmN0aW9uIGNvbnRyb2xXYXJwKGFjdGlvbil7CgogICAgdmFyIG4gPSB7cmVzdGFydDogJ+mHjeWQrycsIHJlX3JlZ2lzdGVyOiAn6YeN5paw5rOo5YaM6I635Y+W5paw6LSm5Y+35LiOSVAnfTsKCiAgICBzaG93QWxlcnQoJ+ato+WcqCcgKyAoblthY3Rpb25dfHxhY3Rpb24pICsgJyBXQVJQIOacjeWKoS4uLicsICdpbmZvJyk7CgogICAgZmV0Y2goJy9hcGkvd2FycC9jb250cm9sJywgewoKICAgICAgICBtZXRob2Q6ICdQT1NUJywKCiAgICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbid9LAoKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7YWN0aW9uOiBhY3Rpb259KQoKICAgIH0pLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oZD0+ewoKICAgICAgICBpZihkLnN1Y2Nlc3MpewoKICAgICAgICAgICAgc2hvd0FsZXJ0KCfmk43kvZzmiJDlip86ICcgKyAoZC5tZXNzYWdlfHwnV0FSUCDmnI3liqHlt7Lmm7TmlrAnKSwgJ29rJyk7CgogICAgICAgICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7IGNoZWNrV2FycFN0YXR1cyhmYWxzZSk7IH0sIDE1MDApOwoKICAgICAgICB9IGVsc2UgewoKICAgICAgICAgICAgc2hvd0FsZXJ0KCfmk43kvZzlpLHotKU6ICcgKyBkLmVycm9yLCAnZXJyJyk7CgogICAgICAgIH0KCiAgICB9KS5jYXRjaChmdW5jdGlvbihlKXsgc2hvd0FsZXJ0KCfor7fmsYLlvILluLg6ICcgKyBlLCAnZXJyJyk7IH0pOwoKfQoKCgpmdW5jdGlvbiB0b2dnbGVIeTJXYXJwKG1vZGUpewoKICAgIHZhciBtc2cgPSAobW9kZSA9PT0gJ2dsb2JhbCcpID8gJ+S4gOmUruWQr+eUqOWFqOWxgOi1sCBXQVJQJyA6ICgobW9kZSA9PT0gJ3VubG9jaycpID8gJ+S4gOmUruWQr+eUqOa1geWqkuS9ky9BSSDop6PplIHliIbmtYEnIDogJ+WFs+mXrSBXQVJQIOWIhua1gScpOwoKICAgIHNob3dBbGVydCgn5q2j5Zyo6YWN572uOiAnICsgbXNnICsgJyDlubbph43lkK8gSHlzdGVyaWEgMi4uLicsICdpbmZvJyk7CgogICAgZmV0Y2goJy9hcGkvd2FycC90b2dnbGVfaHkyJywgewoKICAgICAgICBtZXRob2Q6ICdQT1NUJywKCiAgICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbid9LAoKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7bW9kZTogbW9kZX0pCgogICAgfSkudGhlbihyPT5yLmpzb24oKSkudGhlbihkPT57CgogICAgICAgIGlmKGQuc3VjY2Vzcyl7CgogICAgICAgICAgICBzaG93QWxlcnQoJ+KchSAnICsgbXNnICsgJyDmiJDlip/lubblt7LnlJ/mlYjvvIEnLCAnb2snKTsKCiAgICAgICAgICAgIGxvYWRBbGxDb25maWcoKTsKCiAgICAgICAgICAgIHNldFRpbWVvdXQoZnVuY3Rpb24oKXsgY2hlY2tXYXJwU3RhdHVzKGZhbHNlKTsgfSwgMTUwMCk7CgogICAgICAgIH0gZWxzZSB7CgogICAgICAgICAgICBzaG93QWxlcnQoJ+KdjCDphY3nva7lpLHotKU6ICcgKyBkLmVycm9yLCAnZXJyJyk7CgogICAgICAgIH0KCiAgICB9KS5jYXRjaChmdW5jdGlvbihlKXsgc2hvd0FsZXJ0KCfor7fmsYLlvILluLg6ICcgKyBlLCAnZXJyJyk7IH0pOwoKfQoKCgoKCgoKLy8gLS0tLS0tLS0tLSDlhajlsYDnirbmgIEgLS0tLS0tLS0tLQoKdmFyIGN1cnJlbnRDb25maWcgPSBudWxsOwoKdmFyIGFjdGl2ZVZpZXdNb2RlID0gJ2d1aSc7Cgp2YXIgYWN0aXZlU3ViVGFiID0gJ3NlcnZlcic7Cgp2YXIgc2VydmVyUHVibGljSXAgPSBsb2NhdGlvbi5ob3N0bmFtZTsKCgoKLy8gLS0tLS0tLS0tLSDmqKHmgIHlvLnnqpfmjqfliLYgLS0tLS0tLS0tLQoKZnVuY3Rpb24gb3Blbk1vZGFsKGlkKXsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCkuY2xhc3NMaXN0LmFkZCgnc2hvdycpOwoKfQoKZnVuY3Rpb24gY2xvc2VNb2RhbChpZCl7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKCn0KCgoKLy8gLS0tLS0tLS0tLSDop4blm77liIfmjaIgLS0tLS0tLS0tLQoKCmFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUh5MigpIHsKICAgIGlmKCFjb25maXJtKCLnoa7lrpropoHkvb/nlKjlrpjmlrnohJrmnKzlsIYgSHlzdGVyaWEgMiDmm7TmlrDliLDmnIDmlrDniYjmnKzlkJfvvJ9cbuabtOaWsOWujOaIkOWQjuacjeWKoeS8muiHquWKqOmHjeWQr+OAgiIpKSByZXR1cm47CiAgICAKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC11cGRhdGUnKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgICBsZXQgbG9nQm94ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VwZGF0ZS1sb2ctYm94Jyk7CiAgICBsb2dCb3gudGV4dENvbnRlbnQgPSAn5q2j5Zyo5omn6KGMOiBiYXNoIDwoY3VybCAtZnNTTCBodHRwczovL2dldC5oeTIuc2gvKVxu6K+36ICQ5b+D562J5b6FICjnuqbpnIAxMC0zMOenkikuLi4uLi5cblxuJzsKICAgIAogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2J0bi11cGRhdGUtY2xvc2UnKS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICAgCiAgICB0cnkgewogICAgICAgIGxldCByID0gYXdhaXQgZmV0Y2goJy9hcGkvaHkyL3VwZGF0ZScsIHsKICAgICAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgICAgIGhlYWRlcnM6IHsnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nfSwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoe30pCiAgICAgICAgfSk7CiAgICAgICAgbGV0IHJlcyA9IGF3YWl0IHIuanNvbigpOwogICAgICAgIAogICAgICAgIGxvZ0JveC50ZXh0Q29udGVudCArPSByZXMubG9nOwogICAgICAgIAogICAgICAgIGlmKHJlcy5zdWNjZXNzKSB7CiAgICAgICAgICAgIGxvZ0JveC50ZXh0Q29udGVudCArPSAnXG5cbuKchSDmm7TmlrDmiJDlip/lrozmiJDvvIHor7flhbPpl63lubbliLfmlrDpobXpnaLjgIInOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIGxvZ0JveC50ZXh0Q29udGVudCArPSAnXG5cbuKdjCDmm7TmlrDlpLHotKXvvIzor7fmo4Dmn6XkuIrpnaLml6Xlv5fjgIInOwogICAgICAgIH0KICAgIH0gY2F0Y2goZSkgewogICAgICAgIGxvZ0JveC50ZXh0Q29udGVudCArPSAnXG5cbuKdjCDnvZHnu5zor7fmsYLplJnor686ICcgKyBlOwogICAgfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2J0bi11cGRhdGUtY2xvc2UnKS5zdHlsZS5kaXNwbGF5ID0gJ2lubGluZS1mbGV4JzsKfQoKZnVuY3Rpb24gc3dpdGNoVmlld01vZGUobW9kZSl7CgogICAgYWN0aXZlVmlld01vZGUgPSBtb2RlOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YWItYnRuLWd1aScpLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIG1vZGUgPT09ICdndWknKTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGFiLWJ0bi1yYXcnKS5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCBtb2RlID09PSAncmF3Jyk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1zdWJ0YWJzJykuc3R5bGUuZGlzcGxheSA9IChtb2RlID09PSAnZ3VpJykgPyAnZmxleCcgOiAnbm9uZSc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1jb250YWluZXInKS5zdHlsZS5kaXNwbGF5ID0gKG1vZGUgPT09ICdndWknKSA/ICdmbGV4JyA6ICdub25lJzsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmF3LXBhbmUnKS5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCBtb2RlID09PSAncmF3Jyk7CgogICAgCgogICAgaWYgKG1vZGUgPT09ICdyYXcnKSB7CgogICAgICAgIHN5bmNHdWlUb1Jhd1lhbWwoKTsKCiAgICB9Cgp9CgoKCmZ1bmN0aW9uIHN3aXRjaFN1YlRhYihzdWIpewoKICAgIGFjdGl2ZVN1YlRhYiA9IHN1YjsKCiAgICBbJ3NlcnZlcicsJ291dGJvdW5kcycsJ2FjbCcsJ3F1aWMnLCd3YXJwJywnZXhwb3J0J10uZm9yRWFjaChmdW5jdGlvbihzKXsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N1YnRhYi1idG4tJyArIHMpLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIHMgPT09IHN1Yik7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYW5lLScgKyBzKS5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCBzID09PSBzdWIpOwoKICAgIH0pOwoKICAgIGlmKHN1YiA9PT0gJ2V4cG9ydCcpewoKICAgICAgICB1cGRhdGVFeHBvcnRPdXRwdXRzKCk7CgogICAgfQoKICAgIGlmKHN1YiA9PT0gJ3dhcnAnKXsKCiAgICAgICAgY2hlY2tXYXJwU3RhdHVzKGZhbHNlKTsKCiAgICB9Cgp9CgoKCi8vIC0tLS0tLS0tLS0g5o+Q56S65p2hIC0tLS0tLS0tLS0KCmZ1bmN0aW9uIHNob3dBbGVydChtc2csIHR5cGUpewoKICAgIHZhciBiID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FsZXJ0LWJveCcpOwoKICAgIGIudGV4dENvbnRlbnQgPSBtc2c7CgogICAgYi5jbGFzc05hbWUgPSAnc2hvdyBhbGVydC0nICsgdHlwZTsKCiAgICBjbGVhclRpbWVvdXQoYi5fdCk7CgogICAgaWYodHlwZSAhPT0gJ2luZm8nKSBiLl90ID0gc2V0VGltZW91dChmdW5jdGlvbigpeyBiLmNsYXNzTmFtZSA9ICcnOyB9LCAzNTAwKTsKCn0KCgoKLy8gLS0tLS0tLS0tLSDlr4bnoIHkuI7ovpPlhaXlt6XlhbcgLS0tLS0tLS0tLQoKZnVuY3Rpb24gdG9nZ2xlUGFzc1Zpc2liaWxpdHkoaWQpewoKICAgIHZhciBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKCiAgICBlbC50eXBlID0gKGVsLnR5cGUgPT09ICdwYXNzd29yZCcpID8gJ3RleHQnIDogJ3Bhc3N3b3JkJzsKCn0KCmZ1bmN0aW9uIGdlbmVyYXRlUmFuZG9tUGFzcyhpZCl7CgogICAgdmFyIGNoYXJzID0gJ0FCQ0RFRkdISktMTU5QUVJTVFVWV1hZWmFiY2RlZmdoaWprbW5vcHFyc3R1dnd4eXoyMzQ1Njc4OSFAIyQlXiYqJzsKCiAgICB2YXIgcmVzID0gJyc7CgogICAgZm9yKHZhciBpPTA7IGk8MTY7IGkrKykgcmVzICs9IGNoYXJzLmNoYXJBdChNYXRoLmZsb29yKE1hdGgucmFuZG9tKCkgKiBjaGFycy5sZW5ndGgpKTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCkudmFsdWUgPSByZXM7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLnR5cGUgPSAndGV4dCc7CgogICAgc2hvd0FsZXJ0KCflt7LnlJ/miJDlvLrpmo/mnLrlr4bnoIEnLCAnb2snKTsKCn0KCmZ1bmN0aW9uIGdlbmVyYXRlUmFuZG9tU2VjcmV0KGlkKXsKCiAgICB2YXIgaGV4ID0gJzAxMjM0NTY3ODlhYmNkZWYnOwoKICAgIHZhciByZXMgPSAnJzsKCiAgICBmb3IodmFyIGk9MDsgaTw2NDsgaSsrKSByZXMgKz0gaGV4LmNoYXJBdChNYXRoLmZsb29yKE1hdGgucmFuZG9tKCkgKiBoZXgubGVuZ3RoKSk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLnZhbHVlID0gcmVzOwoKICAgIHNob3dBbGVydCgn5bey55Sf5oiQNjTkvY3lhajmlrAgU2VjcmV0IOWvhumSpScsICdvaycpOwoKfQoKZnVuY3Rpb24gY29weVZhbHVlKGlkKXsKCiAgICB2YXIgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7CgogICAgZWwuc2VsZWN0KCk7CgogICAgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoZWwudmFsdWUpLnRoZW4oZnVuY3Rpb24oKXsKCiAgICAgICAgc2hvd0FsZXJ0KCfinIUg5bey5aSN5Yi25Yiw5Ymq6LS05p2/JywgJ29rJyk7CgogICAgfSkuY2F0Y2goZnVuY3Rpb24oKXsKCiAgICAgICAgZG9jdW1lbnQuZXhlY0NvbW1hbmQoJ2NvcHknKTsKCiAgICAgICAgc2hvd0FsZXJ0KCfinIUg5bey5aSN5Yi25Yiw5Ymq6LS05p2/JywgJ29rJyk7CgogICAgfSk7Cgp9CgpmdW5jdGlvbiBzZXRQcmVzZXRQb3J0KHApewoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktbGlzdGVuJykudmFsdWUgPSAnOicgKyBwOwoKfQoKCgovLyAtLS0tLS0tLS0tIOWKoOi9veWFqOmDqOmFjee9riAtLS0tLS0tLS0tCgpmdW5jdGlvbiBsb2FkQWxsQ29uZmlnKCl7CgogICAgZmV0Y2goJy9hcGkvY29uZmlnL3BhcnNlZCcpLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oZD0+ewoKICAgICAgICBpZighZC5zdWNjZXNzKXsKCiAgICAgICAgICAgIHNob3dBbGVydCgn5Yqg6L296YWN572u5aSx6LSlOiAnICsgKGQuZXJyb3J8fCfmnKrnn6XplJnor68nKSwgJ2VycicpOwoKICAgICAgICAgICAgcmV0dXJuOwoKICAgICAgICB9CgogICAgICAgIGN1cnJlbnRDb25maWcgPSBkLmNvbmZpZzsKCiAgICAgICAgaWYoZC5zZXJ2ZXJfaXApIHNlcnZlclB1YmxpY0lwID0gZC5zZXJ2ZXJfaXA7CgogICAgICAgIAoKICAgICAgICAvLyDmuLLmn5Pln7rnoYDkuI7nvZHnu5wKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1saXN0ZW4nKS52YWx1ZSA9IGN1cnJlbnRDb25maWcubGlzdGVuIHx8ICc6NTEyMzUnOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXBhc3N3b3JkJykudmFsdWUgPSAoY3VycmVudENvbmZpZy5hdXRoICYmIGN1cnJlbnRDb25maWcuYXV0aC5wYXNzd29yZCkgfHwgJyc7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktdGxzLWNlcnQnKS52YWx1ZSA9IChjdXJyZW50Q29uZmlnLnRscyAmJiBjdXJyZW50Q29uZmlnLnRscy5jZXJ0KSB8fCAnL2V0Yy9oeXN0ZXJpYS9jZXJ0LmNydCc7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktdGxzLWtleScpLnZhbHVlID0gKGN1cnJlbnRDb25maWcudGxzICYmIGN1cnJlbnRDb25maWcudGxzLmtleSkgfHwgJy9ldGMvaHlzdGVyaWEvcHJpdmF0ZS5rZXknOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXRscy1zbmknKS52YWx1ZSA9IChjdXJyZW50Q29uZmlnLnRscyAmJiBjdXJyZW50Q29uZmlnLnRscy5zbmkpIHx8ICcnOwoKICAgICAgICAKCiAgICAgICAgdmFyIG0gPSBjdXJyZW50Q29uZmlnLm1hc3F1ZXJhZGUgfHwge307CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktbWFzcS10eXBlJykudmFsdWUgPSBtLnR5cGUgfHwgJ3Byb3h5JzsKCiAgICAgICAgdmFyIG1wID0gbS5wcm94eSB8fCB7fTsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1tYXNxLXVybCcpLnZhbHVlID0gbXAudXJsIHx8ICdodHRwczovL21haW1haS5zZWdhLmpwJzsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1tYXNxLXJld3JpdGUnKS5jaGVja2VkID0gKG1wLnJld3JpdGVIb3N0ICE9PSBmYWxzZSk7CgogICAgICAgIAoKICAgICAgICB2YXIgdHMgPSBjdXJyZW50Q29uZmlnLnRyYWZmaWNTdGF0cyB8fCB7fTsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1zdGF0cy1saXN0ZW4nKS52YWx1ZSA9IHRzLmxpc3RlbiB8fCAnMTI3LjAuMC4xOjE5OTk5JzsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1zdGF0cy1zZWNyZXQnKS52YWx1ZSA9IHRzLnNlY3JldCB8fCAnJzsKCiAgICAgICAgCgogICAgICAgIC8vIOa4suafkyBRVUlDIOS4jumZkOmAnwoKICAgICAgICB2YXIgcSA9IGN1cnJlbnRDb25maWcucXVpYyB8fCB7fTsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLWluaXQtc3RyZWFtJykudmFsdWUgPSBxLmluaXRTdHJlYW1SZWNlaXZlV2luZG93IHx8IDE2Nzc3MjE2OwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXF1aWMtbWF4LXN0cmVhbScpLnZhbHVlID0gcS5tYXhTdHJlYW1SZWNlaXZlV2luZG93IHx8IDE2Nzc3MjE2OwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXF1aWMtaW5pdC1jb25uJykudmFsdWUgPSBxLmluaXRDb25uUmVjZWl2ZVdpbmRvdyB8fCAzMzU1NDQzMjsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLW1heC1jb25uJykudmFsdWUgPSBxLm1heENvbm5SZWNlaXZlV2luZG93IHx8IDMzNTU0NDMyOwoKICAgICAgICAKCiAgICAgICAgdmFyIGJ3ID0gY3VycmVudENvbmZpZy5iYW5kd2lkdGggfHwge307CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktYnctdXAnKS52YWx1ZSA9IGJ3LnVwIHx8ICcnOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLWJ3LWRvd24nKS52YWx1ZSA9IGJ3LmRvd24gfHwgJyc7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktYnctaWdub3JlJykuY2hlY2tlZCA9ICEhY3VycmVudENvbmZpZy5pZ25vcmVDbGllbnRCYW5kd2lkdGg7CgogICAgICAgIAoKICAgICAgICAvLyDmuLLmn5PliJfooagKCiAgICAgICAgcmVuZGVyT3V0Ym91bmRzTGlzdCgpOwoKICAgICAgICByZW5kZXJBY2xMaXN0KCk7CgogICAgICAgIHVwZGF0ZUV4cG9ydE91dHB1dHMoKTsKCiAgICAgICAgCgogICAgICAgIC8vIOWOn+WniyBZQU1MIOi1i+WAvAoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY29uZmlnLWVkaXRvcicpLnZhbHVlID0gZC5yYXcgfHwgJyc7CgogICAgfSkuY2F0Y2goZnVuY3Rpb24oZSl7CgogICAgICAgIHNob3dBbGVydCgn5peg5rOV6I635Y+W6YWN572u5paH5Lu2OiAnICsgZSwgJ2VycicpOwoKICAgIH0pOwoKfQoKCgovLyAtLS0tLS0tLS0tIOWHuuermeWIl+ihqOa4suafkyAtLS0tLS0tLS0tCgpmdW5jdGlvbiByZW5kZXJPdXRib3VuZHNMaXN0KCl7CgogICAgdmFyIGNvbnRhaW5lciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdvdXRib3VuZC1jYXJkcy1jb250YWluZXInKTsKCiAgICBjb250YWluZXIuaW5uZXJIVE1MID0gJyc7CgogICAgdmFyIGxpc3QgPSAoY3VycmVudENvbmZpZyAmJiBjdXJyZW50Q29uZmlnLm91dGJvdW5kcykgfHwgW107CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NvdW50LW9iJykudGV4dENvbnRlbnQgPSBsaXN0Lmxlbmd0aDsKCiAgICAKCiAgICBpZihsaXN0Lmxlbmd0aCA9PT0gMCl7CgogICAgICAgIGNvbnRhaW5lci5pbm5lckhUTUwgPSAnPGRpdiBzdHlsZT0iZ3JpZC1jb2x1bW46MS8tMTt0ZXh0LWFsaWduOmNlbnRlcjtwYWRkaW5nOjMwcHg7Y29sb3I6dmFyKC0tdGV4dC1tdXRlZCkiPuaaguaXoOWHuuermeiKgueCue+8jOeCueWHu+S4iuaWueaMiemSrua3u+WKoDwvZGl2Pic7CgogICAgICAgIHJldHVybjsKCiAgICB9CgogICAgCgogICAgbGlzdC5mb3JFYWNoKGZ1bmN0aW9uKG9iLCBpZHgpewoKICAgICAgICB2YXIgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwoKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICdvYi1jYXJkJzsKCiAgICAgICAgCgogICAgICAgIHZhciB0b3AgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKCiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICdvYi1jYXJkLXRvcCc7CgogICAgICAgIHRvcC5pbm5lckhUTUwgPSAnPHNwYW4gY2xhc3M9Im9iLW5hbWUiPicgKyBlc2NhcGVIdG1sKG9iLm5hbWUpICsgJzwvc3Bhbj4nICsKCiAgICAgICAgICAgICAgICAgICAgICAgICc8c3BhbiBjbGFzcz0ib2ItYmFkZ2UgJyArIG9iLnR5cGUgKyAnIj4nICsgb2IudHlwZS50b1VwcGVyQ2FzZSgpICsgJzwvc3Bhbj4nOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKHRvcCk7CgogICAgICAgIAoKICAgICAgICB2YXIgZGV0YWlscyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwoKICAgICAgICBkZXRhaWxzLmNsYXNzTmFtZSA9ICdvYi1kZXRhaWxzJzsKCiAgICAgICAgaWYob2IudHlwZSA9PT0gJ3NvY2tzNScpewoKICAgICAgICAgICAgdmFyIHM1ID0gb2Iuc29ja3M1IHx8IHt9OwoKICAgICAgICAgICAgZGV0YWlscy5pbm5lckhUTUwgPSAnPGRpdj4mIzEyNzc2MDsgJyArIGVzY2FwZUh0bWwoczUuYWRkciB8fCAnLScpICsgJzwvZGl2PicgKwoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnPGRpdj4mIzEyODEwMDsgJyArIChzNS51c2VybmFtZSA/IGVzY2FwZUh0bWwoczUudXNlcm5hbWUpIDogJzxzcGFuIHN0eWxlPSJjb2xvcjojNjQ3NDhiIj7ml6DorqTor4E8L3NwYW4+JykgKyAnPC9kaXY+JzsKCiAgICAgICAgfSBlbHNlIGlmKG9iLnR5cGUgPT09ICdkaXJlY3QnKXsKCiAgICAgICAgICAgIHZhciBkID0gb2IuZGlyZWN0IHx8IHt9OwoKICAgICAgICAgICAgdmFyIG1vZGVUZXh0ID0gKGQubW9kZSA9PSA2KSA/ICfku4UgSVB2NicgOiAoZC5tb2RlID09IDQgPyAn5LuFIElQdjQnIDogJ+iHquWKqCcpOwoKICAgICAgICAgICAgZGV0YWlscy5pbm5lckhUTUwgPSAnPGRpdj4mIzEyODI2MDsg5qih5byPOiA8Yj4nICsgbW9kZVRleHQgKyAnPC9iPjwvZGl2Pic7CgogICAgICAgIH0gZWxzZSBpZihvYi50eXBlID09PSAnaHR0cCcpewoKICAgICAgICAgICAgdmFyIGggPSBvYi5odHRwIHx8IHt9OwoKICAgICAgICAgICAgZGV0YWlscy5pbm5lckhUTUwgPSAnPGRpdj4mIzEyNzc2MDsgJyArIGVzY2FwZUh0bWwoaC5hZGRyIHx8ICctJykgKyAnPC9kaXY+JzsKCiAgICAgICAgfQoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGRldGFpbHMpOwoKICAgICAgICAKCiAgICAgICAgY2FyZC5pZCA9ICdvYi1jYXJkLScgKyBpZHg7CgogICAgICAgIHZhciB0ZXN0UmVzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CgogICAgICAgIHRlc3RSZXMuY2xhc3NOYW1lID0gJ29iLXRlc3QtcmVzdWx0JzsKCiAgICAgICAgdGVzdFJlcy5pZCA9ICdvYi10ZXN0LScgKyBpZHg7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQodGVzdFJlcyk7CgoKCiAgICAgICAgdmFyIGFjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwoKICAgICAgICBhY3QuY2xhc3NOYW1lID0gJ29iLWFjdGlvbnMnOwoKICAgICAgICBhY3QuaW5uZXJIVE1MID0gJzxidXR0b24gY2xhc3M9ImJ0bi1taW5pIGJ0bi10ZXN0LW9iIiBvbmNsaWNrPSJ0ZXN0T3V0Ym91bmROb2RlKCcgKyBpZHggKyAnLCB0aGlzKSI+JiM5ODg5OyDmtYvor5U8L2J1dHRvbj4nICsKCiAgICAgICAgICAgICAgICAgICAgICAgICc8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgb25jbGljaz0iZWRpdE91dGJvdW5kKCcgKyBpZHggKyAnKSI+JiM5OTk5OyYjNjUwMzk7IOe8lui+kTwvYnV0dG9uPicgKwoKICAgICAgICAgICAgICAgICAgICAgICAgJzxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBzdHlsZT0iY29sb3I6dmFyKC0tZGFuZ2VyKSIgb25jbGljaz0iZGVsZXRlT3V0Ym91bmQoJyArIGlkeCArICcpIj4mIzEyODQ2NTsmIzY1MDM5OyDliKDpmaQ8L2J1dHRvbj4nOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdCk7CgogICAgICAgIAoKICAgICAgICBjb250YWluZXIuYXBwZW5kQ2hpbGQoY2FyZCk7CgogICAgfSk7Cgp9CgoKCmZ1bmN0aW9uIG9wZW5BZGRPdXRib3VuZE1vZGFsKCl7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLXRpdGxlJykudGV4dENvbnRlbnQgPSAn5re75Yqg5Ye656uZ6IqC54K5JzsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItaWR4JykudmFsdWUgPSAnLTEnOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1uYW1lJykudmFsdWUgPSAnJzsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItdHlwZScpLnZhbHVlID0gJ3NvY2tzNSc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLWFkZHInKS52YWx1ZSA9ICcnOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi11c2VyJykudmFsdWUgPSAnJzsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItcGFzcycpLnZhbHVlID0gJyc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLW1vZGUnKS52YWx1ZSA9ICc0JzsKCiAgICB1cGRhdGVPdXRib3VuZE1vZGFsRmllbGRzKCk7CgogICAgb3Blbk1vZGFsKCdtb2RhbC1vdXRib3VuZCcpOwoKfQoKCgpmdW5jdGlvbiBlZGl0T3V0Ym91bmQoaWR4KXsKCiAgICB2YXIgb2IgPSBjdXJyZW50Q29uZmlnLm91dGJvdW5kc1tpZHhdOwoKICAgIGlmKCFvYikgcmV0dXJuOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi10aXRsZScpLnRleHRDb250ZW50ID0gJ+e8lui+keWHuuermeiKgueCuSc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLWlkeCcpLnZhbHVlID0gaWR4OwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1uYW1lJykudmFsdWUgPSBvYi5uYW1lOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi10eXBlJykudmFsdWUgPSBvYi50eXBlOwoKICAgIGlmKG9iLnR5cGUgPT09ICdzb2NrczUnKXsKCiAgICAgICAgdmFyIHM1ID0gb2Iuc29ja3M1IHx8IHt9OwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItYWRkcicpLnZhbHVlID0gczUuYWRkciB8fCAnJzsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLXVzZXInKS52YWx1ZSA9IHM1LnVzZXJuYW1lIHx8ICcnOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItcGFzcycpLnZhbHVlID0gczUucGFzc3dvcmQgfHwgJyc7CgogICAgfSBlbHNlIGlmKG9iLnR5cGUgPT09ICdkaXJlY3QnKXsKCiAgICAgICAgdmFyIGQgPSBvYi5kaXJlY3QgfHwge307CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1tb2RlJykudmFsdWUgPSBkLm1vZGUgfHwgJzQnOwoKICAgIH0gZWxzZSBpZihvYi50eXBlID09PSAnaHR0cCcpewoKICAgICAgICB2YXIgaCA9IG9iLmh0dHAgfHwge307CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1hZGRyJykudmFsdWUgPSBoLmFkZHIgfHwgJyc7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi11c2VyJykudmFsdWUgPSBoLnVzZXJuYW1lIHx8ICcnOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItcGFzcycpLnZhbHVlID0gaC5wYXNzd29yZCB8fCAnJzsKCiAgICB9CgogICAgdXBkYXRlT3V0Ym91bmRNb2RhbEZpZWxkcygpOwoKICAgIG9wZW5Nb2RhbCgnbW9kYWwtb3V0Ym91bmQnKTsKCn0KCgoKZnVuY3Rpb24gdXBkYXRlT3V0Ym91bmRNb2RhbEZpZWxkcygpewoKICAgIHZhciB0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLXR5cGUnKS52YWx1ZTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItcHJveHktZmllbGRzJykuc3R5bGUuZGlzcGxheSA9ICh0ID09PSAnc29ja3M1JyB8fCB0ID09PSAnaHR0cCcpID8gJ2ZsZXgnIDogJ25vbmUnOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1kaXJlY3QtZmllbGRzJykuc3R5bGUuZGlzcGxheSA9ICh0ID09PSAnZGlyZWN0JykgPyAnZmxleCcgOiAnbm9uZSc7Cgp9CgoKCmZ1bmN0aW9uIHNhdmVPdXRib3VuZE1vZGFsKCl7CgogICAgdmFyIGlkeCA9IHBhcnNlSW50KGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1pZHgnKS52YWx1ZSk7CgogICAgdmFyIG5hbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItbmFtZScpLnZhbHVlLnRyaW0oKTsKCiAgICB2YXIgdHlwZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi10eXBlJykudmFsdWU7CgogICAgaWYoIW5hbWUpewoKICAgICAgICBzaG93QWxlcnQoJ+ivt+i+k+WFpeiKgueCueagh+ivhuWQjeensCcsICdlcnInKTsKCiAgICAgICAgcmV0dXJuOwoKICAgIH0KCiAgICAKCiAgICB2YXIgb2IgPSB7bmFtZTogbmFtZSwgdHlwZTogdHlwZX07CgogICAgaWYodHlwZSA9PT0gJ3NvY2tzNScpewoKICAgICAgICB2YXIgYWRkciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1hZGRyJykudmFsdWUudHJpbSgpOwoKICAgICAgICBpZighYWRkcil7IHNob3dBbGVydCgn6K+36L6T5YWl5pyN5Yqh5Zmo5Zyw5Z2AJywgJ2VycicpOyByZXR1cm47IH0KCiAgICAgICAgb2Iuc29ja3M1ID0gewoKICAgICAgICAgICAgYWRkcjogYWRkciwKCiAgICAgICAgICAgIHVzZXJuYW1lOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItdXNlcicpLnZhbHVlLnRyaW0oKSwKCiAgICAgICAgICAgIHBhc3N3b3JkOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtb2ItcGFzcycpLnZhbHVlLnRyaW0oKQoKICAgICAgICB9OwoKICAgIH0gZWxzZSBpZih0eXBlID09PSAnZGlyZWN0Jyl7CgogICAgICAgIHZhciBtb2RlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLW1vZGUnKS52YWx1ZTsKCiAgICAgICAgb2IuZGlyZWN0ID0geyBtb2RlOiAobW9kZSA9PT0gJzQnID8gNCA6IChtb2RlID09PSAnNicgPyA2IDogJ2F1dG8nKSkgfTsKCiAgICB9IGVsc2UgaWYodHlwZSA9PT0gJ2h0dHAnKXsKCiAgICAgICAgdmFyIGFkZHIyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLW9iLWFkZHInKS52YWx1ZS50cmltKCk7CgogICAgICAgIGlmKCFhZGRyMil7IHNob3dBbGVydCgn6K+36L6T5YWl5pyN5Yqh5Zmo5Zyw5Z2AJywgJ2VycicpOyByZXR1cm47IH0KCiAgICAgICAgb2IuaHR0cCA9IHsKCiAgICAgICAgICAgIGFkZHI6IGFkZHIyLAoKICAgICAgICAgICAgdXNlcm5hbWU6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi11c2VyJykudmFsdWUudHJpbSgpLAoKICAgICAgICAgICAgcGFzc3dvcmQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1vYi1wYXNzJykudmFsdWUudHJpbSgpCgogICAgICAgIH07CgogICAgfQoKICAgIAoKICAgIGlmKCFjdXJyZW50Q29uZmlnLm91dGJvdW5kcykgY3VycmVudENvbmZpZy5vdXRib3VuZHMgPSBbXTsKCiAgICBpZihpZHggPj0gMCl7CgogICAgICAgIGN1cnJlbnRDb25maWcub3V0Ym91bmRzW2lkeF0gPSBvYjsKCiAgICB9IGVsc2UgewoKICAgICAgICBjdXJyZW50Q29uZmlnLm91dGJvdW5kcy5wdXNoKG9iKTsKCiAgICB9CgogICAgY2xvc2VNb2RhbCgnbW9kYWwtb3V0Ym91bmQnKTsKCiAgICByZW5kZXJPdXRib3VuZHNMaXN0KCk7CgogICAgc2hvd0FsZXJ0KCflt7Lmm7TmlrDlh7rnq5noioLngrnliJfooajvvIzorrDlvpfngrnlh7vlj7PkuIrop5Lkv53lrZjvvIEnLCAnb2snKTsKCn0KCgoKZnVuY3Rpb24gZGVsZXRlT3V0Ym91bmQoaWR4KXsKCiAgICBpZighY29uZmlybSgn56Gu5a6a6KaB5Yig6Zmk5Ye656uZ6IqC54K5ICcgKyBjdXJyZW50Q29uZmlnLm91dGJvdW5kc1tpZHhdLm5hbWUgKyAnIOWQl++8nycpKSByZXR1cm47CgogICAgY3VycmVudENvbmZpZy5vdXRib3VuZHMuc3BsaWNlKGlkeCwgMSk7CgogICAgcmVuZGVyT3V0Ym91bmRzTGlzdCgpOwoKICAgIHNob3dBbGVydCgn5Ye656uZ6IqC54K55bey56e76ZmkJywgJ29rJyk7Cgp9CgoKCi8vIC0tLS0tLS0tLS0gQUNMIOinhOWImea4suafkyAtLS0tLS0tLS0tCgpmdW5jdGlvbiByZW5kZXJBY2xMaXN0KCl7CgogICAgdmFyIHRib2R5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FjbC10YWJsZS1ib2R5Jyk7CgogICAgdGJvZHkuaW5uZXJIVE1MID0gJyc7CgogICAgdmFyIHJ1bGVzID0gKGN1cnJlbnRDb25maWcgJiYgY3VycmVudENvbmZpZy5hY2wgJiYgY3VycmVudENvbmZpZy5hY2wucnVsZXMpIHx8IFtdOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjb3VudC1hY2wnKS50ZXh0Q29udGVudCA9IHJ1bGVzLmxlbmd0aDsKCiAgICAKCiAgICBpZihydWxlcy5sZW5ndGggPT09IDApewoKICAgICAgICB0Ym9keS5pbm5lckhUTUwgPSAnPHRyPjx0ZCBjb2xzcGFuPSI1IiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXI7cGFkZGluZzoyNHB4O2NvbG9yOnZhcigtLXRleHQtbXV0ZWQpIj7mmoLml6AgQUNMIOWIhua1geinhOWIme+8jOeCueWHu+WPs+S4iuinkua3u+WKoDwvdGQ+PC90cj4nOwoKICAgICAgICByZXR1cm47CgogICAgfQoKICAgIAoKICAgIHJ1bGVzLmZvckVhY2goZnVuY3Rpb24ociwgaWR4KXsKCiAgICAgICAgdmFyIHRyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgndHInKTsKCiAgICAgICAgdHIuaW5uZXJIVE1MID0gJzx0ZD4jJyArIChpZHggKyAxKSArICc8L3RkPicgKwoKICAgICAgICAgICAgJzx0ZD48ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjJweCI+JyArCgogICAgICAgICAgICAgICAgJzxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJtb3ZlQWNsKCcgKyBpZHggKyAnLC0xKSIgdGl0bGU9IuS4iuenuyIgJyArIChpZHg9PT0wPydkaXNhYmxlZCBzdHlsZT0ib3BhY2l0eTowLjMiJzonJykgKyAnPiYjOTY1MDs8L2J1dHRvbj4nICsKCiAgICAgICAgICAgICAgICAnPGJ1dHRvbiBjbGFzcz0iYnRuLW1pbmkiIG9uY2xpY2s9Im1vdmVBY2woJyArIGlkeCArICcsMSkiIHRpdGxlPSLkuIvnp7siICcgKyAoaWR4PT09cnVsZXMubGVuZ3RoLTE/J2Rpc2FibGVkIHN0eWxlPSJvcGFjaXR5OjAuMyInOicnKSArICc+JiM5NjYwOzwvYnV0dG9uPicgKwoKICAgICAgICAgICAgJzwvZGl2PjwvdGQ+JyArCgogICAgICAgICAgICAnPHRkPjxzcGFuIGNsYXNzPSJhY2wtdGFnIj4nICsgZXNjYXBlSHRtbChyLm91dGJvdW5kIHx8ICco55u06L+eL+WFnOW6lSknKSArICc8L3NwYW4+PC90ZD4nICsKCiAgICAgICAgICAgICc8dGQ+JyArIGVzY2FwZUh0bWwoci5ydWxlIHx8ICcnKSArICc8L3RkPicgKwoKICAgICAgICAgICAgJzx0ZCBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI+JyArCgogICAgICAgICAgICAgICAgJzxidXR0b24gY2xhc3M9ImJ0bi1taW5pIiBvbmNsaWNrPSJlZGl0QWNsKCcgKyBpZHggKyAnKSI+JiM5OTk5OyYjNjUwMzk7PC9idXR0b24+ICcgKwoKICAgICAgICAgICAgICAgICc8YnV0dG9uIGNsYXNzPSJidG4tbWluaSIgc3R5bGU9ImNvbG9yOnZhcigtLWRhbmdlcikiIG9uY2xpY2s9ImRlbGV0ZUFjbCgnICsgaWR4ICsgJykiPiYjMTI4NDY1OyYjNjUwMzk7PC9idXR0b24+JyArCgogICAgICAgICAgICAnPC90ZD4nOwoKICAgICAgICB0Ym9keS5hcHBlbmRDaGlsZCh0cik7CgogICAgfSk7Cgp9CgoKCmZ1bmN0aW9uIG1vdmVBY2woaWR4LCBkaXIpewoKICAgIHZhciBydWxlcyA9IGN1cnJlbnRDb25maWcuYWNsLnJ1bGVzOwoKICAgIHZhciB0YXJnZXQgPSBpZHggKyBkaXI7CgogICAgaWYodGFyZ2V0IDwgMCB8fCB0YXJnZXQgPj0gcnVsZXMubGVuZ3RoKSByZXR1cm47CgogICAgdmFyIHRtcCA9IHJ1bGVzW2lkeF07CgogICAgcnVsZXNbaWR4XSA9IHJ1bGVzW3RhcmdldF07CgogICAgcnVsZXNbdGFyZ2V0XSA9IHRtcDsKCiAgICByZW5kZXJBY2xMaXN0KCk7Cgp9CgoKCmZ1bmN0aW9uIG9wZW5BZGRBY2xNb2RhbCgpewoKICAgIHBvcHVsYXRlQWNsT3V0Ym91bmRPcHRpb25zKCk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLWFjbC10aXRsZScpLnRleHRDb250ZW50ID0gJ+a3u+WKoOWIhua1geinhOWImSc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLWFjbC1pZHgnKS52YWx1ZSA9ICctMSc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLWFjbC1ydWxlJykudmFsdWUgPSAnJzsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtYWNsLWhlbHBlcicpLnZhbHVlID0gJyc7CgogICAgb3Blbk1vZGFsKCdtb2RhbC1hY2wnKTsKCn0KCgoKZnVuY3Rpb24gZWRpdEFjbChpZHgpewoKICAgIHBvcHVsYXRlQWNsT3V0Ym91bmRPcHRpb25zKCk7CgogICAgdmFyIHIgPSBjdXJyZW50Q29uZmlnLmFjbC5ydWxlc1tpZHhdOwoKICAgIGlmKCFyKSByZXR1cm47CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLWFjbC10aXRsZScpLnRleHRDb250ZW50ID0gJ+e8lui+keWIhua1geinhOWImSc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLWFjbC1pZHgnKS52YWx1ZSA9IGlkeDsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtYWNsLW91dGJvdW5kJykudmFsdWUgPSByLm91dGJvdW5kOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1hY2wtcnVsZScpLnZhbHVlID0gci5ydWxlOwoKICAgIG9wZW5Nb2RhbCgnbW9kYWwtYWNsJyk7Cgp9CgoKCmZ1bmN0aW9uIHBvcHVsYXRlQWNsT3V0Ym91bmRPcHRpb25zKCl7CgogICAgdmFyIHNlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtb2RhbC1hY2wtb3V0Ym91bmQnKTsKCiAgICBzZWwuaW5uZXJIVE1MID0gJyc7CgogICAgdmFyIGxpc3QgPSAoY3VycmVudENvbmZpZyAmJiBjdXJyZW50Q29uZmlnLm91dGJvdW5kcykgfHwgW107CgogICAgbGlzdC5mb3JFYWNoKGZ1bmN0aW9uKG9iKXsKCiAgICAgICAgdmFyIG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpOwoKICAgICAgICBvcHQudmFsdWUgPSBvYi5uYW1lOwoKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBvYi5uYW1lICsgJyAoJyArIG9iLnR5cGUgKyAnKSc7CgogICAgICAgIHNlbC5hcHBlbmRDaGlsZChvcHQpOwoKICAgIH0pOwoKICAgIC8vIOWGhee9ruebtOi/nuWKqOS9nAoKICAgIHZhciBvcHQxID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnb3B0aW9uJyk7IG9wdDEudmFsdWUgPSAnZGlyZWN0X3Y0Jzsgb3B0MS50ZXh0Q29udGVudCA9ICdkaXJlY3RfdjQgKElQdjQg55u06L+eKSc7IHNlbC5hcHBlbmRDaGlsZChvcHQxKTsKCiAgICB2YXIgb3B0MiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpOyBvcHQyLnZhbHVlID0gJ2RpcmVjdF92Nic7IG9wdDIudGV4dENvbnRlbnQgPSAnZGlyZWN0X3Y2IChJUHY2IOebtOi/niknOyBzZWwuYXBwZW5kQ2hpbGQob3B0Mik7CgogICAgdmFyIG9wdDMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdvcHRpb24nKTsgb3B0My52YWx1ZSA9ICdkaXJlY3QnOyBvcHQzLnRleHRDb250ZW50ID0gJ2RpcmVjdCAo55u06L+eKSc7IHNlbC5hcHBlbmRDaGlsZChvcHQzKTsKCiAgICB2YXIgb3B0NCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpOyBvcHQ0LnZhbHVlID0gJ3JlamVjdCc7IG9wdDQudGV4dENvbnRlbnQgPSAncmVqZWN0ICjmi6bmiKrmi5Lnu50pJzsgc2VsLmFwcGVuZENoaWxkKG9wdDQpOwoKfQoKCgpmdW5jdGlvbiBhcHBseUFjbEhlbHBlcigpewoKICAgIHZhciB2ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21vZGFsLWFjbC1oZWxwZXInKS52YWx1ZTsKCiAgICBpZih2KSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtYWNsLXJ1bGUnKS52YWx1ZSA9IHY7Cgp9CgoKCmZ1bmN0aW9uIHNhdmVBY2xNb2RhbCgpewoKICAgIHZhciBpZHggPSBwYXJzZUludChkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtYWNsLWlkeCcpLnZhbHVlKTsKCiAgICB2YXIgb2IgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtYWNsLW91dGJvdW5kJykudmFsdWU7CgogICAgdmFyIHJ1bGUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbW9kYWwtYWNsLXJ1bGUnKS52YWx1ZS50cmltKCk7CgogICAgaWYoIXJ1bGUpeyBzaG93QWxlcnQoJ+ivt+i+k+WFpeWMuemFjeihqOi+vuW8jycsICdlcnInKTsgcmV0dXJuOyB9CgogICAgCgogICAgdmFyIHIgPSB7b3V0Ym91bmQ6IG9iLCBydWxlOiBydWxlLCByYXc6IG9iICsgJygnICsgcnVsZSArICcpJ307CgogICAgaWYoIWN1cnJlbnRDb25maWcuYWNsKSBjdXJyZW50Q29uZmlnLmFjbCA9IHtydWxlczogW119OwoKICAgIGlmKCFjdXJyZW50Q29uZmlnLmFjbC5ydWxlcykgY3VycmVudENvbmZpZy5hY2wucnVsZXMgPSBbXTsKCiAgICAKCiAgICBpZihpZHggPj0gMCl7CgogICAgICAgIGN1cnJlbnRDb25maWcuYWNsLnJ1bGVzW2lkeF0gPSByOwoKICAgIH0gZWxzZSB7CgogICAgICAgIGN1cnJlbnRDb25maWcuYWNsLnJ1bGVzLnB1c2gocik7CgogICAgfQoKICAgIGNsb3NlTW9kYWwoJ21vZGFsLWFjbCcpOwoKICAgIHJlbmRlckFjbExpc3QoKTsKCiAgICBzaG93QWxlcnQoJ+WIhua1geinhOWImeW3suabtOaWsO+8jOiusOW+l+eCueWHu+WPs+S4iuinkuS/neWtmO+8gScsICdvaycpOwoKfQoKCgpmdW5jdGlvbiBkZWxldGVBY2woaWR4KXsKCiAgICBpZighY29uZmlybSgn56Gu5a6a6KaB5Yig6Zmk6K+l5YiG5rWB6KeE5YiZ5ZCX77yfJykpIHJldHVybjsKCiAgICBjdXJyZW50Q29uZmlnLmFjbC5ydWxlcy5zcGxpY2UoaWR4LCAxKTsKCiAgICByZW5kZXJBY2xMaXN0KCk7Cgp9CgoKCi8vIC0tLS0tLS0tLS0g6LCD5LyY6aKE6K6+IC0tLS0tLS0tLS0KCmZ1bmN0aW9uIGFwcGx5UXVpY1ByZXNldCh0eXBlKXsKCiAgICBpZih0eXBlID09PSAnZXh0cmVtZScpewoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXF1aWMtaW5pdC1zdHJlYW0nKS52YWx1ZSA9IDE2Nzc3MjE2OwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXF1aWMtbWF4LXN0cmVhbScpLnZhbHVlID0gMTY3NzcyMTY7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktcXVpYy1pbml0LWNvbm4nKS52YWx1ZSA9IDMzNTU0NDMyOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXF1aWMtbWF4LWNvbm4nKS52YWx1ZSA9IDMzNTU0NDMyOwoKICAgICAgICBzaG93QWxlcnQoJ+W3sui9veWFpeaegeiHtOaAp+iDvemihOiuvuaWueahiCAoMTZNLzE2TS8zMk0vMzJNKScsICdvaycpOwoKICAgIH0gZWxzZSBpZih0eXBlID09PSAnYmFsYW5jZWQnKXsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLWluaXQtc3RyZWFtJykudmFsdWUgPSA4Mzg4NjA4OwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXF1aWMtbWF4LXN0cmVhbScpLnZhbHVlID0gODM4ODYwODsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLWluaXQtY29ubicpLnZhbHVlID0gMTY3NzcyMTY7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktcXVpYy1tYXgtY29ubicpLnZhbHVlID0gMTY3NzcyMTY7CgogICAgICAgIHNob3dBbGVydCgn5bey6L295YWl5qCH5YeG5Z2H6KGh5pa55qGIICg4TS84TS8xNk0vMTZNKScsICdvaycpOwoKICAgIH0gZWxzZSBpZih0eXBlID09PSAnbGlnaHQnKXsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLWluaXQtc3RyZWFtJykudmFsdWUgPSAyMDk3MTUyOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXF1aWMtbWF4LXN0cmVhbScpLnZhbHVlID0gNDE5NDMwNDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLWluaXQtY29ubicpLnZhbHVlID0gNDE5NDMwNDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLW1heC1jb25uJykudmFsdWUgPSA4Mzg4NjA4OwoKICAgICAgICBzaG93QWxlcnQoJ+W3sui9veWFpeS9juWGheWtmOaWueahiCAoMk0vNE0vNE0vOE0pJywgJ29rJyk7CgogICAgfQoKfQoKCgovLyAtLS0tLS0tLS0tIOiKgueCueWIhuS6q+WvvOWHuiAtLS0tLS0tLS0tCgpmdW5jdGlvbiB1cGRhdGVFeHBvcnRPdXRwdXRzKCl7CgogICAgdmFyIGxpc3RlbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktbGlzdGVuJykudmFsdWUgfHwgJzo1MTIzNSc7CgogICAgdmFyIHBvcnQgPSBsaXN0ZW4ucmVwbGFjZSgvLio6LywgJycpIHx8ICc1MTIzNSc7CgogICAgdmFyIHBhc3MgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXBhc3N3b3JkJykudmFsdWUgfHwgJyc7CgogICAgdmFyIGhvc3QgPSBzZXJ2ZXJQdWJsaWNJcDsKCiAgICB2YXIgc25pID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS10bHMtc25pJykudmFsdWUgfHwgJyc7CgogICAgCgogICAgLy8gVVJJCgogICAgdmFyIHVyaSA9ICdoeXN0ZXJpYTI6Ly8nICsgZW5jb2RlVVJJQ29tcG9uZW50KHBhc3MpICsgJ0AnICsgaG9zdCArICc6JyArIHBvcnQgKyAnLz9pbnNlY3VyZT0xJyArIChzbmkgPyAnJnNuaT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHNuaSkgOiAnJykgKyAnI0h5c3RlcmlhMi1TZXJ2ZXInOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdleHBvcnQtdXJpJykudmFsdWUgPSB1cmk7CgogICAgCgogICAgLy8gQ2xhc2ggTWV0YQoKICAgIHZhciBjbGFzaExpbmVzID0gWwoKICAgICAgICAnLSBuYW1lOiAiSHlzdGVyaWEyLU5vZGUiJywKCiAgICAgICAgJyAgdHlwZTogaHlzdGVyaWEyJywKCiAgICAgICAgJyAgc2VydmVyOiAnICsgaG9zdCwKCiAgICAgICAgJyAgcG9ydDogJyArIHBvcnQsCgogICAgICAgICcgIHBhc3N3b3JkOiAiJyArIHBhc3MgKyAnIicsCgogICAgICAgICcgIHNraXAtY2VydC12ZXJpZnk6IHRydWUnCgogICAgXTsKCiAgICBpZihzbmkpIGNsYXNoTGluZXMucHVzaCgnICBzbmk6ICcgKyBzbmkpOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdleHBvcnQtY2xhc2gnKS52YWx1ZSA9IGNsYXNoTGluZXMuam9pbihTdHJpbmcuZnJvbUNoYXJDb2RlKDEwKSk7CgogICAgCgogICAgLy8gU2luZy1ib3gKCiAgICB2YXIgc2IgPSBKU09OLnN0cmluZ2lmeSh7CgogICAgICAgIHR5cGU6ICdoeXN0ZXJpYTInLAoKICAgICAgICB0YWc6ICdoeTItb3V0JywKCiAgICAgICAgc2VydmVyOiBob3N0LAoKICAgICAgICBzZXJ2ZXJfcG9ydDogcGFyc2VJbnQocG9ydCksCgogICAgICAgIHBhc3N3b3JkOiBwYXNzLAoKICAgICAgICB0bHM6IHsKCiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsCgogICAgICAgICAgICBpbnNlY3VyZTogdHJ1ZSwKCiAgICAgICAgICAgIHNlcnZlcl9uYW1lOiBzbmkgfHwgdW5kZWZpbmVkCgogICAgICAgIH0KCiAgICB9LCBudWxsLCAyKTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZXhwb3J0LXNpbmdib3gnKS52YWx1ZSA9IHNiOwoKfQoKCgovLyAtLS0tLS0tLS0tIOaUtumbhuW9k+WJjSBHVUkg6YWN572u5bm26L2s5Li6IEpTT04gLS0tLS0tLS0tLQoKZnVuY3Rpb24gY29sbGVjdEd1aUNvbmZpZygpewoKICAgIGlmKCFjdXJyZW50Q29uZmlnKSBjdXJyZW50Q29uZmlnID0ge307CgogICAgY3VycmVudENvbmZpZy5saXN0ZW4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLWxpc3RlbicpLnZhbHVlLnRyaW0oKSB8fCAnOjUxMjM1JzsKCiAgICAKCiAgICBpZighY3VycmVudENvbmZpZy5hdXRoKSBjdXJyZW50Q29uZmlnLmF1dGggPSB7dHlwZTogJ3Bhc3N3b3JkJ307CgogICAgY3VycmVudENvbmZpZy5hdXRoLnBhc3N3b3JkID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1wYXNzd29yZCcpLnZhbHVlOwoKICAgIAoKICAgIGlmKCFjdXJyZW50Q29uZmlnLnRscykgY3VycmVudENvbmZpZy50bHMgPSB7fTsKCiAgICBjdXJyZW50Q29uZmlnLnRscy5jZXJ0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS10bHMtY2VydCcpLnZhbHVlLnRyaW0oKTsKCiAgICBjdXJyZW50Q29uZmlnLnRscy5rZXkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLXRscy1rZXknKS52YWx1ZS50cmltKCk7CgogICAgY3VycmVudENvbmZpZy50bHMuc25pID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS10bHMtc25pJykudmFsdWUudHJpbSgpOwoKICAgIAoKICAgIGlmKCFjdXJyZW50Q29uZmlnLm1hc3F1ZXJhZGUpIGN1cnJlbnRDb25maWcubWFzcXVlcmFkZSA9IHt9OwoKICAgIGN1cnJlbnRDb25maWcubWFzcXVlcmFkZS50eXBlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1tYXNxLXR5cGUnKS52YWx1ZTsKCiAgICBpZihjdXJyZW50Q29uZmlnLm1hc3F1ZXJhZGUudHlwZSA9PT0gJ3Byb3h5Jyl7CgogICAgICAgIGN1cnJlbnRDb25maWcubWFzcXVlcmFkZS5wcm94eSA9IHsKCiAgICAgICAgICAgIHVybDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1tYXNxLXVybCcpLnZhbHVlLnRyaW0oKSwKCiAgICAgICAgICAgIHJld3JpdGVIb3N0OiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZ3VpLW1hc3EtcmV3cml0ZScpLmNoZWNrZWQKCiAgICAgICAgfTsKCiAgICB9CgogICAgCgogICAgaWYoIWN1cnJlbnRDb25maWcucXVpYykgY3VycmVudENvbmZpZy5xdWljID0ge307CgogICAgY3VycmVudENvbmZpZy5xdWljLmluaXRTdHJlYW1SZWNlaXZlV2luZG93ID0gcGFyc2VJbnQoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLWluaXQtc3RyZWFtJykudmFsdWUpIHx8IDE2Nzc3MjE2OwoKICAgIGN1cnJlbnRDb25maWcucXVpYy5tYXhTdHJlYW1SZWNlaXZlV2luZG93ID0gcGFyc2VJbnQoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLW1heC1zdHJlYW0nKS52YWx1ZSkgfHwgMTY3NzcyMTY7CgogICAgY3VycmVudENvbmZpZy5xdWljLmluaXRDb25uUmVjZWl2ZVdpbmRvdyA9IHBhcnNlSW50KGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktcXVpYy1pbml0LWNvbm4nKS52YWx1ZSkgfHwgMzM1NTQ0MzI7CgogICAgY3VycmVudENvbmZpZy5xdWljLm1heENvbm5SZWNlaXZlV2luZG93ID0gcGFyc2VJbnQoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1xdWljLW1heC1jb25uJykudmFsdWUpIHx8IDMzNTU0NDMyOwoKICAgIAoKICAgIGlmKCFjdXJyZW50Q29uZmlnLmJhbmR3aWR0aCkgY3VycmVudENvbmZpZy5iYW5kd2lkdGggPSB7fTsKCiAgICBjdXJyZW50Q29uZmlnLmJhbmR3aWR0aC51cCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktYnctdXAnKS52YWx1ZS50cmltKCk7CgogICAgY3VycmVudENvbmZpZy5iYW5kd2lkdGguZG93biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktYnctZG93bicpLnZhbHVlLnRyaW0oKTsKCiAgICBjdXJyZW50Q29uZmlnLmlnbm9yZUNsaWVudEJhbmR3aWR0aCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdndWktYnctaWdub3JlJykuY2hlY2tlZDsKCiAgICAKCiAgICBpZighY3VycmVudENvbmZpZy50cmFmZmljU3RhdHMpIGN1cnJlbnRDb25maWcudHJhZmZpY1N0YXRzID0ge307CgogICAgY3VycmVudENvbmZpZy50cmFmZmljU3RhdHMubGlzdGVuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1zdGF0cy1saXN0ZW4nKS52YWx1ZS50cmltKCk7CgogICAgY3VycmVudENvbmZpZy50cmFmZmljU3RhdHMuc2VjcmV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2d1aS1zdGF0cy1zZWNyZXQnKS52YWx1ZS50cmltKCk7CgogICAgCgogICAgcmV0dXJuIGN1cnJlbnRDb25maWc7Cgp9CgoKCi8vIC0tLS0tLS0tLS0g5ZCM5q2lIEdVSSDliLAgUmF3IFlBTUwg6aKE6KeIIC0tLS0tLS0tLS0KCmZ1bmN0aW9uIHN5bmNHdWlUb1Jhd1lhbWwoKXsKCiAgICB2YXIgY2ZnID0gY29sbGVjdEd1aUNvbmZpZygpOwoKICAgIGZldGNoKCcvYXBpL2NvbmZpZy9wcmV2aWV3X3lhbWwnLCB7CgogICAgICAgIG1ldGhvZDogJ1BPU1QnLAoKICAgICAgICBoZWFkZXJzOiB7J0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJ30sCgogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHtjb25maWc6IGNmZ30pCgogICAgfSkudGhlbihyPT5yLmpzb24oKSkudGhlbihkPT57CgogICAgICAgIGlmKGQuc3VjY2Vzcyl7CgogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY29uZmlnLWVkaXRvcicpLnZhbHVlID0gZC55YW1sOwoKICAgICAgICB9CgogICAgfSkuY2F0Y2goZnVuY3Rpb24oKXt9KTsKCn0KCgoKLy8gLS0tLS0tLS0tLSDkv53lrZjphY3nva4gLS0tLS0tLS0tLQoKZnVuY3Rpb24gc2F2ZUFjdGl2ZUNvbmZpZyhyZXN0YXJ0U2VydmljZSl7CgogICAgaWYoYWN0aXZlVmlld01vZGUgPT09ICdndWknKXsKCiAgICAgICAgdmFyIGNmZyA9IGNvbGxlY3RHdWlDb25maWcoKTsKCiAgICAgICAgc2hvd0FsZXJ0KCfij7Mg5q2j5Zyo5L+d5a2Y6YWN572uLi4uJywgJ2luZm8nKTsKCiAgICAgICAgZmV0Y2goJy9hcGkvY29uZmlnL2d1aScsIHsKCiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLAoKICAgICAgICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbid9LAoKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoe2NvbmZpZzogY2ZnLCByZXN0YXJ0OiByZXN0YXJ0U2VydmljZX0pCgogICAgICAgIH0pLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oZD0+ewoKICAgICAgICAgICAgaWYoZC5zdWNjZXNzKXsKCiAgICAgICAgICAgICAgICBzaG93QWxlcnQocmVzdGFydFNlcnZpY2UgPyAn4pyFIOmFjee9ruW3suS/neWtmOW5tuaIkOWKn+mHjeWQr+acjeWKoe+8gScgOiAn4pyFIOmFjee9ruW3suaIkOWKn+S/neWtmO+8gScsICdvaycpOwoKICAgICAgICAgICAgICAgIHNldFRpbWVvdXQodXBkYXRlU3RhdHVzLCAxNTAwKTsKCiAgICAgICAgICAgIH0gZWxzZSB7CgogICAgICAgICAgICAgICAgc2hvd0FsZXJ0KCfinYwg5L+d5a2Y5aSx6LSlOiAnICsgZC5lcnJvciwgJ2VycicpOwoKICAgICAgICAgICAgfQoKICAgICAgICB9KS5jYXRjaChmdW5jdGlvbihlKXsgc2hvd0FsZXJ0KCfinYwg6K+35rGC5aSx6LSlOiAnICsgZSwgJ2VycicpOyB9KTsKCiAgICB9IGVsc2UgewoKICAgICAgICB2YXIgY29udGVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjb25maWctZWRpdG9yJykudmFsdWU7CgogICAgICAgIHNob3dBbGVydCgn4o+zIOato+WcqOS/neWtmOWOn+Wni+mFjee9ri4uLicsICdpbmZvJyk7CgogICAgICAgIGZldGNoKCcvYXBpL2NvbmZpZycsIHsKCiAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLAoKICAgICAgICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbid9LAoKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoe2NvbnRlbnQ6IGNvbnRlbnQsIHJlc3RhcnQ6IHJlc3RhcnRTZXJ2aWNlfSkKCiAgICAgICAgfSkudGhlbihyPT5yLmpzb24oKSkudGhlbihkPT57CgogICAgICAgICAgICBpZihkLnN1Y2Nlc3MpewoKICAgICAgICAgICAgICAgIHNob3dBbGVydChyZXN0YXJ0U2VydmljZSA/ICfinIUg5Y6f5aeLIFlBTUwg5bey5L+d5a2Y5bm25oiQ5Yqf6YeN5ZCv5pyN5Yqh77yBJyA6ICfinIUg5Y6f5aeLIFlBTUwg5bey5oiQ5Yqf5L+d5a2Y77yBJywgJ29rJyk7CgogICAgICAgICAgICAgICAgbG9hZEFsbENvbmZpZygpOwoKICAgICAgICAgICAgICAgIHNldFRpbWVvdXQodXBkYXRlU3RhdHVzLCAxNTAwKTsKCiAgICAgICAgICAgIH0gZWxzZSB7CgogICAgICAgICAgICAgICAgc2hvd0FsZXJ0KCfinYwg5L+d5a2Y5aSx6LSlOiAnICsgZC5lcnJvciwgJ2VycicpOwoKICAgICAgICAgICAgfQoKICAgICAgICB9KS5jYXRjaChmdW5jdGlvbihlKXsgc2hvd0FsZXJ0KCfinYwg6K+35rGC5aSx6LSlOiAnICsgZSwgJ2VycicpOyB9KTsKCiAgICB9Cgp9CgoKCi8vIC0tLS0tLS0tLS0g5pyN5Yqh5o6n5Yi2IC0tLS0tLS0tLS0KCmZ1bmN0aW9uIGNvbnRyb2xTZXJ2aWNlKGFjdGlvbil7CgogICAgdmFyIG4gPSB7c3RhcnQ6ICflvIDlkK8nLCBzdG9wOiAn5YWz6ZetJywgcmVzdGFydDogJ+mHjeWQryd9OwoKICAgIHNob3dBbGVydCgn4o+zIOato+WcqCcgKyBuW2FjdGlvbl0gKyAn5pyN5YqhLi4uJywgJ2luZm8nKTsKCiAgICBmZXRjaCgnL2FwaS9zZXJ2aWNlJywgewoKICAgICAgICBtZXRob2Q6ICdQT1NUJywKCiAgICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbid9LAoKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7YWN0aW9uOiBhY3Rpb259KQoKICAgIH0pLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oZD0+ewoKICAgICAgICBzaG93QWxlcnQoZC5zdWNjZXNzID8gJ+KchSAnICsgZC5tZXNzYWdlIDogJ+KdjCAnICsgZC5tZXNzYWdlLCBkLnN1Y2Nlc3MgPyAnb2snIDogJ2VycicpOwoKICAgICAgICBzZXRUaW1lb3V0KHVwZGF0ZVN0YXR1cywgMTUwMCk7CgogICAgfSkuY2F0Y2goZnVuY3Rpb24oKXsgc2hvd0FsZXJ0KCfinYwg6K+35rGC5aSx6LSlJywgJ2VycicpOyB9KTsKCn0KCgoKZnVuY3Rpb24gdXBkYXRlU3RhdHVzKCl7CgogICAgZmV0Y2goJy9hcGkvc3RhdHVzJykudGhlbihyPT5yLmpzb24oKSkudGhlbihkPT57CgogICAgICAgIHZhciBiYWRnZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0dXMtYmFkZ2UnKTsKCiAgICAgICAgdmFyIHR4dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0dXMtdGV4dCcpOwoKICAgICAgICBpZihkLnJ1bm5pbmcpewoKICAgICAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gJ2JhZGdlLXN0YXR1cyc7CgogICAgICAgICAgICB0eHQudGV4dENvbnRlbnQgPSAn6L+Q6KGM5LitJzsKCiAgICAgICAgfSBlbHNlIHsKCiAgICAgICAgICAgIGJhZGdlLmNsYXNzTmFtZSA9ICdiYWRnZS1zdGF0dXMgc3RvcHBlZCc7CgogICAgICAgICAgICB0eHQudGV4dENvbnRlbnQgPSAn5bey5YGc5q2iJzsKCiAgICAgICAgfQoKICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCl7CgogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0dXMtYmFkZ2UnKS5jbGFzc05hbWUgPSAnYmFkZ2Utc3RhdHVzIHN0b3BwZWQnOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdHVzLXRleHQnKS50ZXh0Q29udGVudCA9ICfnprvnur8gLyDml6Dms5Xov57mjqUnOwoKICAgIH0pOwoKfQoKCgpmdW5jdGlvbiB1cGRhdGVTeXNpbmZvKCl7CgogICAgZmV0Y2goJy9hcGkvc3lzaW5mbycpLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oZD0+ewoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2ktY3B1JykudGV4dENvbnRlbnQgPSBkLmNwdSArICclJzsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLW1lbScpLnRleHRDb250ZW50ID0gZC5tZW0udXNlZCArICdNIC8gJyArIGQubWVtLnRvdGFsICsgJ00nOwoKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2ktZGlzaycpLnRleHRDb250ZW50ID0gZC5kaXNrLnVzZWQgKyAnIC8gJyArIGQuZGlzay50b3RhbDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLXJ4JykudGV4dENvbnRlbnQgPSBkLm5ldC5yeDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLXR4JykudGV4dENvbnRlbnQgPSBkLm5ldC50eDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLXJ4LXNwZWVkJykudGV4dENvbnRlbnQgPSBkLm5ldC5yeF9zcGVlZDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLXR4LXNwZWVkJykudGV4dENvbnRlbnQgPSBkLm5ldC50eF9zcGVlZDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLXRjcCcpLnRleHRDb250ZW50ID0gZC5jb25uLnRjcDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLXVkcCcpLnRleHRDb250ZW50ID0gZC5jb25uLnVkcDsKCiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpLWh5c3Qtc3RhcnQnKS50ZXh0Q29udGVudCA9IGQuaHlzdF9zdGFydDsKCiAgICB9KS5jYXRjaChmdW5jdGlvbigpe30pOwoKfQoKCgovLyAtLS0tLS0tLS0tIOaXpeW/l+S4jui/nuaOpeebkeaOpyAtLS0tLS0tLS0tCgp2YXIgbW9uaXRvclRhYiA9ICdsb2cnOyB2YXIgY29ublRpbWVyID0gbnVsbDsKCmZ1bmN0aW9uIHN3aXRjaE1vbml0b3JUYWIodCl7CgogICAgbW9uaXRvclRhYiA9IHQ7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RhYi1idG4tbG9nJykuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgdCA9PT0gJ2xvZycpOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YWItYnRuLWNvbm4nKS5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLCB0ID09PSAnY29ubicpOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2ctY29udGVudCcpLnN0eWxlLmRpc3BsYXkgPSAodCA9PT0gJ2xvZycpID8gJycgOiAnbm9uZSc7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Nvbm4tY29udGVudCcpLnN0eWxlLmRpc3BsYXkgPSAodCA9PT0gJ2Nvbm4nKSA/ICcnIDogJ25vbmUnOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2ctY29udHJvbHMnKS5zdHlsZS5kaXNwbGF5ID0gKHQgPT09ICdsb2cnKSA/ICcnIDogJ25vbmUnOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjb25uLWNvbnRyb2xzJykuc3R5bGUuZGlzcGxheSA9ICh0ID09PSAnY29ubicpID8gJycgOiAnbm9uZSc7CgogICAgaWYodCA9PT0gJ2Nvbm4nKXsKCiAgICAgICAgbG9hZFN0cmVhbXMoKTsKCiAgICAgICAgaWYoIWNvbm5UaW1lcikgY29ublRpbWVyID0gc2V0SW50ZXJ2YWwobG9hZFN0cmVhbXMsIDMwMDApOwoKICAgIH0gZWxzZSBpZihjb25uVGltZXIpewoKICAgICAgICBjbGVhckludGVydmFsKGNvbm5UaW1lcik7IGNvbm5UaW1lciA9IG51bGw7CgogICAgfQoKfQoKCgp2YXIgbG9nQXV0b1JlZnJlc2ggPSB0cnVlOyB2YXIgbG9nVGltZXIgPSBudWxsOyB2YXIgbG9nTGluZXMgPSBbXTsgdmFyIGxvZ1NpZyA9ICcnOyB2YXIgbG9nQ3Vyc29yID0gbnVsbDsgdmFyIGxvZ1NvdXJjZSA9ICcnOwoKZnVuY3Rpb24gcmVuZGVyTG9nQ291bnQobiwgZXh0cmEpewoKICAgIHZhciBub3cgPSBuZXcgRGF0ZSgpOwoKICAgIHZhciB0cyA9IG5vdy50b1RpbWVTdHJpbmcoKS5zbGljZSgwLCA4KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9nLWxpbmUtY291bnQnKS50ZXh0Q29udGVudCA9IG4gKyAnIGxpbmVzJyArIChsb2dTb3VyY2UgPyAnIMK3ICcgKyBsb2dTb3VyY2UgOiAnJykgKyAnIHwgJyArIHRzICsgKGV4dHJhfHwnJyk7Cgp9CgpmdW5jdGlvbiBsb2FkTG9ncygpewoKICAgIGZldGNoKCcvYXBpL2xvZ3MnKS50aGVuKHI9PnIuanNvbigpKS50aGVuKGQ9PnsKCiAgICAgICAgaWYoIWQgfHwgIUFycmF5LmlzQXJyYXkoZC5sb2dzKSkgcmV0dXJuOwoKICAgICAgICBsb2dTb3VyY2UgPSBkLnNvdXJjZSB8fCAnJzsKCiAgICAgICAgdmFyIGxjID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZy1jb250ZW50Jyk7CgogICAgICAgIHZhciBsaW5lcyA9IGQubG9nczsKCiAgICAgICAgaWYobG9nQ3Vyc29yICE9PSBudWxsKXsKCiAgICAgICAgICAgIHZhciBpID0gbGluZXMubGFzdEluZGV4T2YobG9nQ3Vyc29yKTsKCiAgICAgICAgICAgIGxpbmVzID0gKGkgPj0gMCkgPyBsaW5lcy5zbGljZShpICsgMSkgOiBsaW5lczsKCiAgICAgICAgfQoKICAgICAgICB2YXIgc2lnID0gbGluZXMuam9pbihTdHJpbmcuZnJvbUNoYXJDb2RlKDApKTsKCiAgICAgICAgaWYoc2lnID09PSBsb2dTaWcpIHJldHVybjsKCiAgICAgICAgbG9nU2lnID0gc2lnOwoKICAgICAgICB2YXIgb2xkSGVpZ2h0ID0gbGMuc2Nyb2xsSGVpZ2h0OwoKICAgICAgICB2YXIgYXRCb3R0b20gPSBsYy5zY3JvbGxUb3AgKyBsYy5jbGllbnRIZWlnaHQgPj0gb2xkSGVpZ2h0IC0gMzA7CgogICAgICAgIGxjLmlubmVySFRNTCA9ICcnOwoKICAgICAgICBsb2dMaW5lcyA9IGxpbmVzOwoKICAgICAgICBsaW5lcy5mb3JFYWNoKGZ1bmN0aW9uKGxpbmUpewoKICAgICAgICAgICAgdmFyIGRpdiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwoKICAgICAgICAgICAgZGl2LnN0eWxlLnBhZGRpbmcgPSAnMXB4IDAnOwoKICAgICAgICAgICAgZGl2LnRleHRDb250ZW50ID0gbGluZTsKCiAgICAgICAgICAgIGxjLmFwcGVuZENoaWxkKGRpdik7CgogICAgICAgIH0pOwoKICAgICAgICByZW5kZXJMb2dDb3VudChsaW5lcy5sZW5ndGgsIGxvZ0N1cnNvciAhPT0gbnVsbCA/ICcgwrcg5LuF5paw5aKeJyA6ICcnKTsKCiAgICAgICAgaWYoYXRCb3R0b20gJiYgbGluZXMubGVuZ3RoID4gMCkgbGMuc2Nyb2xsVG9wID0gbGMuc2Nyb2xsSGVpZ2h0OwoKICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCl7fSk7Cgp9CgpmdW5jdGlvbiBjbGVhckxvZ3MoKXsKCiAgICBsb2dDdXJzb3IgPSBsb2dMaW5lcy5sZW5ndGggPyBsb2dMaW5lc1tsb2dMaW5lcy5sZW5ndGggLSAxXSA6IG51bGw7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZy1jb250ZW50JykuaW5uZXJIVE1MID0gJyc7CgogICAgbG9nU2lnID0gJyc7CgogICAgcmVuZGVyTG9nQ291bnQoMCwgJyDCtyDku4XmlrDlop4nKTsKCn0KCmZ1bmN0aW9uIHRvZ2dsZUF1dG9SZWZyZXNoKCl7CgogICAgbG9nQXV0b1JlZnJlc2ggPSAhbG9nQXV0b1JlZnJlc2g7CgogICAgdmFyIGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2ctYXV0by1idG4nKTsKCiAgICBpZihsb2dBdXRvUmVmcmVzaCl7CgogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICfij7jvuI8nOwoKICAgICAgICBsb2dTaWcgPSAnJzsgbG9nQ3Vyc29yID0gbnVsbDsKCiAgICAgICAgbG9hZExvZ3MoKTsKCiAgICAgICAgbG9nVGltZXIgPSBzZXRJbnRlcnZhbChsb2FkTG9ncywgMzAwMCk7CgogICAgfSBlbHNlIHsKCiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gJ+KWtu+4jyc7CgogICAgICAgIGNsZWFySW50ZXJ2YWwobG9nVGltZXIpOwoKICAgIH0KCn0KCgoKZnVuY3Rpb24gZm10Qnl0ZXMoYil7CgogICAgYiA9IE51bWJlcihiKSB8fCAwOwoKICAgIGlmKGIgPCAxMDI0KSByZXR1cm4gYiArICcgQic7CgogICAgdmFyIHUgPSBbJ0tCJywnTUInLCdHQicsJ1RCJ10sIGkgPSAtMTsKCiAgICB3aGlsZShiID49IDEwMjQgJiYgaSA8IHUubGVuZ3RoIC0gMSl7IGIgLz0gMTAyNDsgaSsrOyB9CgogICAgcmV0dXJuIGIudG9GaXhlZCgxKSArICcgJyArIHVbaV07Cgp9CgpmdW5jdGlvbiBmbXREdXIocyl7CgogICAgcyA9IE1hdGgubWF4KDAsIE1hdGgucm91bmQoTnVtYmVyKHMpIHx8IDApKTsKCiAgICBpZihzIDwgNjApIHJldHVybiBzICsgJ3MnOwoKICAgIGlmKHMgPCAzNjAwKSByZXR1cm4gTWF0aC5mbG9vcihzIC8gNjApICsgJ20nICsgU3RyaW5nKHMgJSA2MCkucGFkU3RhcnQoMiwgJzAnKSArICdzJzsKCiAgICByZXR1cm4gTWF0aC5mbG9vcihzIC8gMzYwMCkgKyAnaCcgKyBTdHJpbmcoTWF0aC5mbG9vcihzICUgMzYwMCAvIDYwKSkucGFkU3RhcnQoMiwgJzAnKSArICdtJzsKCn0KCmZ1bmN0aW9uIGxvYWRTdHJlYW1zKCl7CgogICAgZmV0Y2goJy9hcGkvc3RyZWFtcycpLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oZD0+ewoKICAgICAgICBpZighZCB8fCAhQXJyYXkuaXNBcnJheShkLnRhcmdldHMpKSByZXR1cm47CgogICAgICAgIHZhciBib3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY29ubi1jb250ZW50Jyk7CgogICAgICAgIHZhciBzdGFtcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjb25uLXVwZGF0ZWQnKTsKCiAgICAgICAgYm94LnRleHRDb250ZW50ID0gJyc7CgogICAgICAgIGlmKGQuZXJyb3IpewoKICAgICAgICAgICAgdmFyIGVtID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CgogICAgICAgICAgICBlbS5jbGFzc05hbWUgPSAnY29ubi1lbXB0eSc7CgogICAgICAgICAgICBlbS50ZXh0Q29udGVudCA9ICfnu5/orqEgQVBJIOS4jeWPr+eUqDogJyArIGQuZXJyb3I7CgogICAgICAgICAgICBib3guYXBwZW5kQ2hpbGQoZW0pOwoKICAgICAgICAgICAgc3RhbXAudGV4dENvbnRlbnQgPSAnJzsKCiAgICAgICAgICAgIHJldHVybjsKCiAgICAgICAgfQoKICAgICAgICB2YXIgbm93ID0gbmV3IERhdGUoKTsKCiAgICAgICAgc3RhbXAudGV4dENvbnRlbnQgPSAn5rS76LeD5rWBICcgKyBkLmxpdmVfY291bnQgKyAnIMK3IOebruaghyAnICsgZC50YXJnZXRfY291bnQgKyAnIMK3ICcgKyBub3cudG9UaW1lU3RyaW5nKCkuc2xpY2UoMCwgOCk7CgogICAgICAgIHZhciB0YiA9IDAsIHJiID0gMDsKCiAgICAgICAgZC50YXJnZXRzLmZvckVhY2goZnVuY3Rpb24oeCl7IHRiICs9IHgudHg7IHJiICs9IHgucng7IH0pOwoKICAgICAgICB2YXIgcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwoKICAgICAgICBzLmNsYXNzTmFtZSA9ICdjb25uLXN1bW1hcnknOwoKICAgICAgICBbWyfkuIrooYzlkIjorqEnLCBmbXRCeXRlcyh0YildLCBbJ+S4i+ihjOWQiOiuoScsIGZtdEJ5dGVzKHJiKV0sIFsn5ZCI6K6hJywgZm10Qnl0ZXModGIgKyByYildXS5mb3JFYWNoKGZ1bmN0aW9uKHApewoKICAgICAgICAgICAgdmFyIHNwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpOwoKICAgICAgICAgICAgc3AudGV4dENvbnRlbnQgPSBwWzBdICsgJyAnOwoKICAgICAgICAgICAgdmFyIGIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdiJyk7CgogICAgICAgICAgICBiLnRleHRDb250ZW50ID0gcFsxXTsKCiAgICAgICAgICAgIHNwLmFwcGVuZENoaWxkKGIpOwoKICAgICAgICAgICAgcy5hcHBlbmRDaGlsZChzcCk7CgogICAgICAgIH0pOwoKICAgICAgICBib3guYXBwZW5kQ2hpbGQocyk7CgogICAgICAgIGlmKCFkLnRhcmdldHMubGVuZ3RoKXsKCiAgICAgICAgICAgIHZhciBlMiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwoKICAgICAgICAgICAgZTIuY2xhc3NOYW1lID0gJ2Nvbm4tZW1wdHknOwoKICAgICAgICAgICAgZTIudGV4dENvbnRlbnQgPSAn5pqC5peg6L+e5o6l6K6w5b2VJzsKCiAgICAgICAgICAgIGJveC5hcHBlbmRDaGlsZChlMik7CgogICAgICAgICAgICByZXR1cm47CgogICAgICAgIH0KCiAgICAgICAgdmFyIHRibCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3RhYmxlJyk7CgogICAgICAgIHRibC5jbGFzc05hbWUgPSAnY29ubi10YWJsZSc7CgogICAgICAgIHZhciB0aGVhZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3RoZWFkJyk7CgogICAgICAgIHRoZWFkLmlubmVySFRNTCA9ICc8dHI+PHRoPuebruagh+WcsOWdgDwvdGg+PHRoIHN0eWxlPSJ0ZXh0LWFsaWduOnJpZ2h0Ij7mtYHmlbA8L3RoPjx0aCBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI+5LiK6KGMPC90aD48dGggc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPuS4i+ihjDwvdGg+PHRoIHN0eWxlPSJ0ZXh0LWFsaWduOnJpZ2h0Ij7lkIjorqE8L3RoPjx0aCBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI+5pyA6L+R5rS76LeDPC90aD48L3RyPic7CgogICAgICAgIHRibC5hcHBlbmRDaGlsZCh0aGVhZCk7CgogICAgICAgIHZhciB0Ym9keSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3Rib2R5Jyk7CgogICAgICAgIGQudGFyZ2V0cy5mb3JFYWNoKGZ1bmN0aW9uKHgpewoKICAgICAgICAgICAgdmFyIHRyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgndHInKTsKCiAgICAgICAgICAgIHRyLmlubmVySFRNTCA9ICc8dGQ+JyArIGVzY2FwZUh0bWwoeC50YXJnZXQpICsgJzwvdGQ+JyArCgogICAgICAgICAgICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nICsgeC5zdHJlYW1zICsgJzwvdGQ+JyArCgogICAgICAgICAgICAgICAgJzx0ZCBjbGFzcz0ibnVtIHR4Ij4nICsgZm10Qnl0ZXMoeC50eCkgKyAnPC90ZD4nICsKCiAgICAgICAgICAgICAgICAnPHRkIGNsYXNzPSJudW0gcngiPicgKyBmbXRCeXRlcyh4LnJ4KSArICc8L3RkPicgKwoKICAgICAgICAgICAgICAgICc8dGQgY2xhc3M9Im51bSI+JyArIGZtdEJ5dGVzKHgudHggKyB4LnJ4KSArICc8L3RkPicgKwoKICAgICAgICAgICAgICAgICc8dGQgY2xhc3M9Im51bSI+JyArIGZtdER1cih4LmlkbGUpICsgJ+WJjTwvdGQ+JzsKCiAgICAgICAgICAgIHRib2R5LmFwcGVuZENoaWxkKHRyKTsKCiAgICAgICAgfSk7CgogICAgICAgIHRibC5hcHBlbmRDaGlsZCh0Ym9keSk7CgogICAgICAgIGJveC5hcHBlbmRDaGlsZCh0YmwpOwoKICAgIH0pLmNhdGNoKGZ1bmN0aW9uKCl7fSk7Cgp9CgoKCmZ1bmN0aW9uIGVzY2FwZUh0bWwocyl7CgogICAgaWYodHlwZW9mIHMgIT09ICdzdHJpbmcnKSBzID0gU3RyaW5nKHN8fCcnKTsKCiAgICByZXR1cm4gcy5yZXBsYWNlKC8mL2csJyZhbXA7JykucmVwbGFjZSgvPC9nLCcmbHQ7JykucmVwbGFjZSgvPi9nLCcmZ3Q7JykucmVwbGFjZSgvIi9nLCcmcXVvdDsnKS5yZXBsYWNlKC8nL2csJyYjMzk7Jyk7Cgp9CgoKCi8vIC0tLS0tLS0tLS0g5ouW5ou95YiG5Ymy5p2hIC0tLS0tLS0tLS0KCihmdW5jdGlvbigpewoKICAgIHZhciBkaXZpZGVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2RpdmlkZXInKTsKCiAgICBpZighZGl2aWRlcikgcmV0dXJuOwoKICAgIHZhciBtYWluID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignLm1haW4nKTsKCiAgICB2YXIgbGVmdCA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJy5tYWluLWxlZnQnKTsKCiAgICB2YXIgcmlnaHQgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcubWFpbi1yaWdodCcpOwoKICAgIHZhciBpc0RyYWdnaW5nID0gZmFsc2U7CgogICAgZGl2aWRlci5hZGRFdmVudExpc3RlbmVyKCdtb3VzZWRvd24nLCBmdW5jdGlvbigpewoKICAgICAgICBpc0RyYWdnaW5nID0gdHJ1ZTsKCiAgICAgICAgZGl2aWRlci5jbGFzc0xpc3QuYWRkKCdhY3RpdmUnKTsKCiAgICAgICAgZG9jdW1lbnQuYm9keS5zdHlsZS5jdXJzb3IgPSAnY29sLXJlc2l6ZSc7CgogICAgICAgIGRvY3VtZW50LmJvZHkuc3R5bGUudXNlclNlbGVjdCA9ICdub25lJzsKCiAgICB9KTsKCiAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdtb3VzZW1vdmUnLCBmdW5jdGlvbihlKXsKCiAgICAgICAgaWYoIWlzRHJhZ2dpbmcpIHJldHVybjsKCiAgICAgICAgdmFyIHJlY3QgPSBtYWluLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpOwoKICAgICAgICB2YXIgb2Zmc2V0ID0gZS5jbGllbnRYIC0gcmVjdC5sZWZ0OwoKICAgICAgICB2YXIgcGN0ID0gTWF0aC5tYXgoMjUsIE1hdGgubWluKDgwLCBvZmZzZXQgLyByZWN0LndpZHRoICogMTAwKSk7CgogICAgICAgIGxlZnQuc3R5bGUuZmxleCA9ICcwIDAgJyArIChwY3QgLSAwLjUpICsgJyUnOwoKICAgICAgICByaWdodC5zdHlsZS53aWR0aCA9ICcnOwoKICAgICAgICByaWdodC5zdHlsZS5mbGV4ID0gJzEgMSAnICsgKDk5LjUgLSBwY3QpICsgJyUnOwoKICAgIH0pOwoKICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ21vdXNldXAnLCBmdW5jdGlvbigpewoKICAgICAgICBpZihpc0RyYWdnaW5nKXsKCiAgICAgICAgICAgIGlzRHJhZ2dpbmcgPSBmYWxzZTsKCiAgICAgICAgICAgIGRpdmlkZXIuY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CgogICAgICAgICAgICBkb2N1bWVudC5ib2R5LnN0eWxlLmN1cnNvciA9ICcnOwoKICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5zdHlsZS51c2VyU2VsZWN0ID0gJyc7CgogICAgICAgIH0KCiAgICB9KTsKCn0pKCk7CgoKCi8vIC0tLS0tLS0tLS0g5Yid5aeL5YyW5ZCv5YqoIC0tLS0tLS0tLS0KCmxvYWRBbGxDb25maWcoKTsKCnVwZGF0ZVN0YXR1cygpOwoKdXBkYXRlU3lzaW5mbygpOwoKbG9hZExvZ3MoKTsKCmxvZ1RpbWVyID0gc2V0SW50ZXJ2YWwobG9hZExvZ3MsIDMwMDApOwoKc2V0SW50ZXJ2YWwodXBkYXRlU3RhdHVzLCA1MDAwKTsKCnNldEludGVydmFsKHVwZGF0ZVN5c2luZm8sIDMwMDApOwoKCgoKCjwvc2NyaXB0PgoKCjwhLS0gVXBkYXRlIE1vZGFsIC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IiBpZD0ibW9kYWwtdXBkYXRlIj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWJveCIgc3R5bGU9IndpZHRoOiA1NDBweDsiPgogICAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWhlYWRlciI+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLXRpdGxlIj7mm7TmlrAgSHlzdGVyaWEgMiDmoLjlv4M8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLWJnLW1haW4pO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOjZweDtwYWRkaW5nOjEycHg7Zm9udC1mYW1pbHk6bW9ub3NwYWNlO2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXRleHQtbWFpbik7bWluLWhlaWdodDoyMDBweDttYXgtaGVpZ2h0OjQwMHB4O292ZXJmbG93LXk6YXV0bzt3aGl0ZS1zcGFjZTpwcmUtd3JhcDsiIGlkPSJ1cGRhdGUtbG9nLWJveCI+5YeG5aSH5LiL6L295pu05pawLi4uPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtZm9vdGVyIj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zYXZlIiBvbmNsaWNrPSJsb2NhdGlvbi5yZWxvYWQoKSIgaWQ9ImJ0bi11cGRhdGUtY2xvc2UiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPuWFs+mXreW5tuWIt+aWsDwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgPC9kaXY+CjwvZGl2PgoKPC9ib2R5PgoKPC9odG1sPg=="""

def get_login_html():
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'login.html'),
        '/etc/hysteria/templates/login.html'
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                pass
    return HTML_LOGIN


def get_index_html():
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'index.html'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html'),
        '/etc/hysteria/templates/index.html'
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                pass
    return base64.b64decode(_B64_HTML_TEMPLATE).decode('utf-8')



# ---------- 双栈监听服务 ----------
class DualStackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class ManagerHandler(http.server.BaseHTTPRequestHandler):

    def _finish_headers(self, code, ctype, length, extra=()):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(length))
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()

    def _send_html(self, code, html):
        body = html.encode('utf-8')
        self._finish_headers(code, 'text/html; charset=utf-8', len(body))
        self.wfile.write(body)

    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self._finish_headers(code, 'application/json; charset=utf-8', len(body))
        self.wfile.write(body)

    def _redirect(self, location, cookie=None):
        extra = [('Location', location)]
        if cookie is not None:
            extra.append(('Set-Cookie', cookie))
        self._finish_headers(302, 'text/plain; charset=utf-8', 0, extra)

    def _read_body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except (TypeError, ValueError):
            n = 0
        if n <= 0:
            return b''
        if n > MAX_BODY:
            return None
        return self.rfile.read(n)

    # ---------- GET 路由 ----------
    def do_GET(self):
        path = urlparse(self.path).path

        if path == '/logout':
            self._redirect('/login', 'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict')
            return

        if path == '/login':
            if check_auth(self):
                self._redirect('/')
                return
            self._send_html(200, get_login_html().replace('__ERROR__', '密码错误，请重试'))
            return

        if not check_auth(self):
            self._redirect('/login')
            return

        if path == '/':
            self._send_html(200, get_index_html())
        elif path == '/api/status':
            self._send_json(200, {'running': service_is_active()})
        elif path == '/api/config':
            try:
                with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                    self._send_json(200, {'content': f.read()})
            except Exception as e:
                self._send_json(500, {'error': str(e)})
        elif path == '/api/config/parsed':
            try:
                with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                    raw = f.read()
                cfg, err = parse_yaml_config(raw)
                if err:
                    self._send_json(500, {'success': False, 'error': err})
                else:
                    host = self.headers.get('Host', '').partition(':')[0]
                    self._send_json(200, {
                        'success': True,
                        'config': cfg,
                        'raw': raw,
                        'server_ip': get_server_ip(self)
                    })
            except Exception as e:
                self._send_json(500, {'success': False, 'error': str(e)})
        elif path == '/api/sysinfo':
            self._send_json(200, {
                'cpu': get_cpu_percent(),
                'mem': get_mem_info(),
                'disk': get_disk_info(),
                'net': get_net_info(),
                'conn': get_conn_count(),
                'hyst_start': get_hysteria2_start_time(),
            })
        elif path == '/api/logs':
            try:
                lines, source = read_logs()
                self._send_json(200, {'logs': lines, 'source': source})
            except Exception as e:
                self._send_json(500, {'logs': [], 'source': 'error', 'error': str(e)})
        elif path == '/api/warp/status':
            self._send_json(200, get_warp_status())
        elif path == '/api/streams':
            try:
                self._send_json(200, streams_snapshot())
            except Exception as e:
                self._send_json(500, {'live': [], 'targets': [], 'error': str(e)})
        else:
            self._finish_headers(404, 'text/plain; charset=utf-8', 0)

    # ---------- POST 路由 ----------
    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        if body is None:
            self._finish_headers(413, 'text/plain; charset=utf-8', 0)
            return

        if path == '/login':
            self._handle_login(body)
            return

        if not check_auth(self):
            self._send_json(401, {'error': 'unauthorized'})
            return

        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except Exception:
            self._send_json(400, {'success': False, 'error': 'invalid JSON'})
            return
        if not isinstance(data, dict):
            self._send_json(400, {'success': False, 'error': 'invalid payload'})
            return

        if path == '/api/outbound/test':
            self._send_json(200, test_outbound_curl(data))

        elif path == '/api/warp/status':
            self._send_json(200, get_warp_status())

        elif path == '/api/warp/control':
            action = data.get('action')
            if action == 'restart':
                r = subprocess.run(['systemctl', 'restart', 'hysteria-warp.service'],
                                   capture_output=True, text=True, timeout=15)
                success = (r.returncode == 0)
                msg = 'WARP 服务已重启' if success else f'重启失败: {r.stderr.strip()}'
                self._send_json(200, {'success': success, 'message': msg})
            elif action == 're_register':
                self._send_json(200, register_warp_account())
            else:
                self._send_json(400, {'success': False, 'error': '无效的操作指令'})

        elif path == '/api/warp/toggle_hy2':
            mode = data.get('mode')
            self._send_json(200, toggle_hy2_warp_route(mode))

        elif path == '/api/config/preview_yaml':
            cfg = data.get('config')
            if not isinstance(cfg, dict):
                self._send_json(400, {'success': False, 'error': 'missing config'})
                return
            try:
                yml = generate_yaml(cfg)
                self._send_json(200, {'success': True, 'yaml': yml})
            except Exception as e:
                self._send_json(500, {'success': False, 'error': str(e)})

        elif path == '/api/config/gui':
            cfg = data.get('config')
            if not isinstance(cfg, dict):
                self._send_json(400, {'success': False, 'error': 'missing config'})
                return
            try:
                new_yaml = generate_yaml(cfg)
                # 校验 YAML 语法
                yaml.safe_load(new_yaml)
                # 备份并写入
                backup_config()
                with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                    f.write(new_yaml)

                restart = bool(data.get('restart'))
                if restart:
                    subprocess.run(['systemctl', 'restart', SERVICE_NAME],
                                   capture_output=True, text=True, timeout=60)
                self._send_json(200, {'success': True, 'restarted': restart})
            except Exception as e:
                self._send_json(500, {'success': False, 'error': str(e)})

        elif path == '/api/config':
            content = data.get('content')
            if not isinstance(content, str):
                self._send_json(400, {'success': False, 'error': 'missing content'})
                return
            try:
                # 校验 YAML 语法
                yaml.safe_load(content)
                backup_config()
                with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                    f.write(content)
                restart = bool(data.get('restart'))
                if restart:
                    subprocess.run(['systemctl', 'restart', SERVICE_NAME],
                                   capture_output=True, text=True, timeout=60)
                self._send_json(200, {'success': True, 'restarted': restart})
            except Exception as e:
                self._send_json(500, {'success': False, 'error': str(e)})

        elif path == '/api/service':
            action = data.get('action')
            if action in ('start', 'stop', 'restart'):
                result = subprocess.run(['systemctl', action, SERVICE_NAME],
                                        capture_output=True, text=True, timeout=60)
                success = result.returncode == 0
                msg = '服务 {} 成功'.format(action) if success else \
                      '操作失败: {}'.format(result.stderr.strip() or result.stdout.strip())
                self._send_json(200, {'success': success, 'message': msg})
            else:
                self._send_json(400, {'success': False, 'message': 'invalid action'})
        else:
            self._finish_headers(404, 'text/plain; charset=utf-8', 0)

    def _handle_login(self, body):
        ip = _norm_ip(self)
        remain = login_lock_remaining(ip)
        if remain > 0:
            self._redirect('/login?error=locked')
            return

        password = ''
        try:
            password = json.loads(body.decode('utf-8')).get('password', '')
        except Exception:
            try:
                password = parse_qs(body.decode('utf-8')).get('password', [''])[0]
            except Exception:
                password = ''

        if password and hmac.compare_digest(
                str(password).encode('utf-8'), PASSWORD.encode('utf-8')):
            login_clear(ip)
            token = create_token()
            self._redirect('/',
                           'session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}'.format(
                               token, SESSION_TTL))
        else:
            login_record_fail(ip)
            self._redirect('/login?error=1')

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    start_stats_sampler()
    print(f"[INFO] Hysteria 2 Manager starting on [::]:{PORT}")
    print(f"[INFO] Config path: {CONFIG_PATH}")
    print(f"[INFO] Service name: {SERVICE_NAME}")
    if yaml is None:
        print("[WARN] ⚠️ 未检测到 PyYAML 库！YAML 解析与编辑功能将受限。请安装: apt install python3-yaml 或 pip install pyyaml")
    if PASSWORD == 'admin123':
        print("[WARN] ⚠️ Using default password 'admin123'! Please set HYST_MANAGER_PASSWORD in your environment or service file for production security.")
    else:
        print("[INFO] Password authentication configured.")
    with DualStackServer(("::", PORT), ManagerHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[INFO] Hysteria 2 Manager stopped.")
