# MC 离线启动器 · 联机信令服务器 + 公开反馈网站 + 加密代理
# 部署到 pythonanywhere（账号 IDSFFX）：创建 Web App，上传本文件为 main.py。
# 作用：
#   1) 房间配对 / P2P 打洞配对信令（只登记/查询地址，不转发游戏数据）；
#   2) 公开反馈网站（所有访客可见全部反馈、可提交自己的反馈）；
#   3) 加密代理 /api/proxy（启动器第三方 JSON 请求经此加密转发，隐藏发送者、链路加密）。
#
# 安全：所有信令请求参数经 AES-256-CBC 整体加密为 ?enc=<b64> 传输，
#       目标（网络名/地址）、发送者（机器码/IP）、信息（密码/端口）均为密文；
#       响应同样加密回传。明文请求（老客户端）兼容保留。
import json
import os
import time
import base64
import hashlib
import ipaddress
from urllib.parse import urlparse

from flask import Flask, request, jsonify

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

app = Flask(__name__)

# ============ AES-256-CBC 加密（与启动器 SecureNet 约定一致） ============
_AES_KEY = hashlib.sha256(b'MC-Launcher-Net-DataKey-v2').digest()


def _aes_dec(b64):
    """解密 ?enc= 载荷（base64(iv+密文)）→ dict；失败返回 None。"""
    if not _HAS_CRYPTO or not b64:
        return None
    try:
        raw = base64.b64decode(b64)
        iv, ct = raw[:16], raw[16:]
        c = AES.new(_AES_KEY, AES.MODE_CBC, iv)
        return json.loads(unpad(c.decrypt(ct), 16).decode('utf-8'))
    except Exception:
        return None


def _aes_enc(obj):
    """加密响应 → {"enc": "base64(iv+密文)"} 的载荷字符串。"""
    try:
        iv = os.urandom(16)
        c = AES.new(_AES_KEY, AES.MODE_CBC, iv)
        ct = c.encrypt(pad(json.dumps(obj, ensure_ascii=False).encode('utf-8'), 16))
        return base64.b64encode(iv + ct).decode()
    except Exception:
        return None


def _unpack():
    """统一取参：GET args + POST form；若带 enc 则解密后并入（加密字段优先）。"""
    p = {}
    if request.method == 'POST' and request.form:
        p.update({k: v for k, v in request.form.items()})
    p.update({k: v for k, v in request.args.items()})
    enc = p.pop('enc', None)
    if enc:
        d = _aes_dec(enc)
        if isinstance(d, dict):
            for k, v in d.items():
                p[k] = str(v)
    return p


def _has_enc():
    if 'enc' in request.args or 'enc' in request.form:
        return True
    return False


def _out(obj, code=200):
    """响应：请求带 enc 则整体加密回传（{"enc": ...}），否则明文 jsonify。"""
    if _has_enc():
        e = _aes_enc(obj)
        if e:
            return jsonify(enc=e), code
    return jsonify(obj), code


# ============ 房间配对（明文/加密兼容） ============
# rooms: code -> {addr, used, ts}
rooms = {}
MAX_ROOMS = 500
TTL = 60 * 10  # 房间 10 分钟无人操作自动清理


def _pubip():
    return (request.headers.get('X-Forwarded-For') or '').split(',')[0].strip() \
           or (request.remote_addr or '0.0.0.0')


@app.route('/')
def index():
    return 'MC 离线启动器联机信令服务 OK'


@app.route('/api/room/create', methods=['GET', 'POST'])
def create():
    p = _unpack()
    code = (p.get('code') or '').strip().upper()
    port = (p.get('port') or '').strip()
    if not code or not port.isdigit():
        return _out({'ok': False, 'msg': '缺房间号或端口'}, 400)
    if len(rooms) >= MAX_ROOMS:
        return _out({'ok': False, 'msg': '服务器房间已满'}, 503)
    ip = _pubip()
    addr = "%s:%s" % (ip, port)
    rooms[code] = {'addr': addr, 'used': False, 'ts': time.time()}
    return _out({'ok': True, 'code': code, 'addr': addr})


@app.route('/api/room/create_addr', methods=['GET', 'POST'])
def create_addr():
    p = _unpack()
    code = (p.get('code') or '').strip().upper()
    addr = (p.get('addr') or '').strip()
    if not code or not addr:
        return _out({'ok': False, 'msg': '缺房间号或地址'}, 400)
    if len(rooms) >= MAX_ROOMS:
        return _out({'ok': False, 'msg': '服务器房间已满'}, 503)
    rooms[code] = {'addr': addr, 'used': False, 'ts': time.time()}
    return _out({'ok': True, 'code': code, 'addr': addr})


@app.route('/api/room/join', methods=['GET', 'POST'])
def join():
    p = _unpack()
    code = (p.get('code') or '').strip().upper()
    r = rooms.get(code)
    if not r:
        return _out({'ok': False, 'msg': '房间不存在或已过期'}, 404)
    if r['used']:
        return _out({'ok': False, 'msg': '该地址已被使用（一次性）'}, 410)
    r['used'] = True
    return _out({'ok': True, 'code': code, 'addr': r['addr']})


@app.route('/api/room/status', methods=['GET'])
def status():
    p = _unpack()
    code = (p.get('code') or '').strip().upper()
    r = rooms.get(code)
    if not r:
        return _out({'ok': False, 'msg': '房间不存在或已过期'}, 404)
    return _out({'ok': True, 'code': code, 'addr': r['addr'], 'used': r['used']})


# ============ 自研虚拟局域网（纯 P2P 打洞配对，加密信令） ============
# pythonanywhere 只做配对信令（交换双方公网 IP + 打洞端口），不转发游戏数据。
import hashlib as _hl

# networks: name(lower) -> {passh, host_ip, host_port, mcport, player_ip, player_port, ts}
networks = {}
NET_TTL = 60 * 30  # 网络 30 分钟无人操作自动清理


def _h(p):
    return _hl.sha256((p or '').encode('utf-8')).hexdigest()


@app.route('/api/p2p/ping', methods=['GET'])
def p2p_ping():
    return 'ok'


@app.route('/api/p2p/host', methods=['GET', 'POST'])
def p2p_host():
    p = _unpack()
    name = (p.get('name') or '').strip().lower()
    passh = _h(p.get('pass'))
    lh = (p.get('lh') or '').strip()
    mcport = (p.get('mcport') or '').strip()
    machine = (p.get('machine') or '').strip()
    if not name or not lh or not mcport:
        return _out({'ok': False, 'msg': '缺网络名/打洞端口/MC端口'}, 400)
    if len(networks) >= 200:
        return _out({'ok': False, 'msg': '服务器网络已满'}, 503)
    networks[name] = {'passh': passh, 'host_ip': _pubip(), 'host_port': lh,
                      'mcport': mcport, 'player_ip': '', 'player_port': '',
                      'machine': machine, 'ts': time.time()}
    return _out({'ok': True, 'name': name, 'ip': networks[name]['host_ip'],
                 'port': lh, 'mcport': mcport})


@app.route('/api/p2p/delete', methods=['GET', 'POST'])
def p2p_delete():
    # 删除网络：仅创建该网络的机器（机器码匹配 + 密码正确）可删
    p = _unpack()
    name = (p.get('name') or '').strip().lower()
    passh = _h(p.get('pass'))
    machine = (p.get('machine') or '').strip()
    n = networks.get(name)
    if not n:
        return _out({'ok': False, 'msg': '网络不存在或已过期'}, 404)
    if n['passh'] != passh:
        return _out({'ok': False, 'msg': '网络名或密码错误'}, 401)
    if not n.get('machine') or n['machine'] != machine:
        return _out({'ok': False, 'msg': '机器码不匹配，仅创建该网络的电脑可删除'}, 403)
    networks.pop(name, None)
    return _out({'ok': True, 'name': name})


@app.route('/api/p2p/join', methods=['GET', 'POST'])
def p2p_join():
    p = _unpack()
    name = (p.get('name') or '').strip().lower()
    passh = _h(p.get('pass'))
    lh = (p.get('lh') or '').strip()
    n = networks.get(name)
    if not n:
        return _out({'ok': False, 'msg': '网络不存在或已过期'}, 404)
    if n['passh'] != passh:
        return _out({'ok': False, 'msg': '网络名或密码错误'}, 401)
    n['player_ip'] = _pubip()
    n['player_port'] = lh
    n['ts'] = time.time()
    return _out({'ok': True, 'name': name,
                 'host_ip': n['host_ip'], 'host_port': n['host_port'], 'mcport': n['mcport'],
                 'my_ip': n['player_ip'], 'my_port': lh})


@app.route('/api/p2p/peer', methods=['GET', 'POST'])
def p2p_peer():
    # 房主（或玩家）查询对方公网端点，用于双向打洞
    p = _unpack()
    name = (p.get('name') or '').strip().lower()
    passh = _h(p.get('pass'))
    n = networks.get(name)
    if not n:
        return _out({'ok': False, 'msg': '网络不存在或已过期'}, 404)
    if n['passh'] != passh:
        return _out({'ok': False, 'msg': '网络名或密码错误'}, 401)
    n['ts'] = time.time()
    return _out({'ok': True, 'name': name,
                 'host_ip': n['host_ip'], 'host_port': n['host_port'],
                 'player_ip': n['player_ip'], 'player_port': n['player_port'],
                 'mcport': n['mcport']})


# ============ 加密代理 /api/proxy ============
# 启动器第三方 JSON 请求（版本清单、Mod 列表、加载器元数据、更新检查、翻译等）
# 经此加密转发：第三方只见本服务器 IP（隐藏发送者），本机→服务器链路应用层加密。
import urllib.request
import urllib.error
import socket

_PROXY_BODY_MAX = 8 * 1024 * 1024  # 响应体上限 8MB（免费版内存 512MB，JSON 接口足够）


def _is_private(host):
    if host in ('localhost', '0.0.0.0'):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved \
               or ip.is_multicast or ip.is_unspecified
    except ValueError:
        pass
    try:
        for info in socket.getaddrinfo(host, None):
            try:
                a = ipaddress.ip_address(info[4][0])
                if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved \
                        or a.is_multicast or a.is_unspecified:
                    return True
            except ValueError:
                continue
    except Exception:
        pass
    return False


@app.route('/api/proxy', methods=['GET', 'POST'])
def api_proxy():
    p = _unpack()
    url = (p.get('url') or '').strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        return _out({'ok': False, 'code': 0, 'msg': '仅支持 http/https 目标'}, 400)
    try:
        host = urlparse(url).hostname
    except Exception:
        host = None
    if not host or _is_private(host):
        return _out({'ok': False, 'code': 0, 'msg': '目标地址不合法'}, 400)
    method = (p.get('method') or 'GET').upper()
    if method not in ('GET', 'POST', 'HEAD'):
        return _out({'ok': False, 'code': 0, 'msg': '不支持的请求方法'}, 400)
    body = p.get('body') or ''
    ctype = p.get('ctype')
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) MC-Launcher/1.0',
        'Accept': '*/*',
    }
    if ctype:
        headers['Content-Type'] = ctype
    try:
        data = body.encode('utf-8') if (method == 'POST' and body) else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=20) as r:
            code = r.getcode()
            raw = r.read(_PROXY_BODY_MAX + 1)[:_PROXY_BODY_MAX]
            return _out({'ok': True, 'code': code,
                         'body': base64.b64encode(raw).decode(), 'msg': ''})
    except urllib.error.HTTPError as e:
        # 目标返回非 2xx：把错误状态码与响应体回传，供客户端判断（如 GitHub 404）
        try:
            raw = e.read(_PROXY_BODY_MAX + 1)[:_PROXY_BODY_MAX]
        except Exception:
            raw = b''
        return _out({'ok': True, 'code': e.code,
                     'body': base64.b64encode(raw).decode(), 'msg': ''})
    except Exception as e:
        return _out({'ok': False, 'code': 0,
                     'msg': (str(e) or '网络错误')[:200]}, 502)


# ============ 公开反馈网站 ============
# 任何访客打开 /feedback 都能看到所有人的反馈，并提交自己的反馈。
FEEDBACK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'feedback.txt')
MAX_FEEDBACK = 300          # 页面最多展示条数
_fb_recent = {}             # ip -> ts，简单限流（60 秒 1 条）


def _esc(s):
    return (s or '').replace('&', '&amp;').replace('<', '&lt;') \
                    .replace('>', '&gt;').replace('"', '&quot;')


def _fb_load():
    out = []
    try:
        with open(FEEDBACK_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return out


def _fb_append(item):
    try:
        with open(FEEDBACK_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    except Exception:
        pass


def _fb_page():
    items = _fb_load()
    cards = ''
    for it in items[-MAX_FEEDBACK:]:
        ts = it.get('ts', 0)
        t = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
        name = (it.get('name') or '匿名').strip() or '匿名'
        text = (it.get('text') or '').strip()
        cards += ('<div class="card"><div class="card-h"><span class="name">%s</span>'
                  '<span class="time">%s</span></div><div class="card-b">%s</div></div>'
                  % (_esc(name), t, _esc(text)))
    if not cards:
        cards = '<div class="empty">还没有反馈，来发第一条吧～</div>'
    return PAGE_TPL.replace('__CARDS__', cards)


PAGE_TPL = '''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MC 离线启动器 · 反馈中心</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#eef5ff;font-family:"Microsoft YaHei","PingFang SC",sans-serif;color:#1f2d3d}
.wrap{max-width:760px;margin:0 auto;padding:24px 16px 60px}
.head{background:linear-gradient(135deg,#3b82f6,#60a5fa);border-radius:14px;padding:22px 24px;color:#fff;box-shadow:0 4px 14px rgba(59,130,246,.25)}
.head h1{font-size:20px;margin-bottom:4px}
.head p{font-size:13px;opacity:.9}
.panel{background:#fff;border-radius:14px;padding:18px;margin-top:16px;box-shadow:0 2px 10px rgba(31,45,61,.06)}
.panel h2{font-size:15px;margin-bottom:12px;color:#3b82f6}
.row{display:flex;gap:10px;margin-bottom:10px}
.row input{flex:1;border:1px solid #dbe6f5;border-radius:8px;padding:9px 12px;font-size:13px;outline:none}
.row input:focus{border-color:#3b82f6}
textarea{width:100%;border:1px solid #dbe6f5;border-radius:8px;padding:9px 12px;font-size:13px;min-height:88px;resize:vertical;outline:none;font-family:inherit}
textarea:focus{border-color:#3b82f6}
.btn{background:linear-gradient(135deg,#3b82f6,#60a5fa);border:0;border-radius:8px;color:#fff;padding:10px 22px;font-size:13px;cursor:pointer;margin-top:10px}
.btn:hover{filter:brightness(1.06)}
.btn:disabled{opacity:.6;cursor:default}
.tip{font-size:12px;color:#8a94a6;margin-top:8px}
.card{background:#f7fbff;border:1px solid #e3edfb;border-radius:10px;padding:12px 14px;margin-bottom:10px}
.card-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.name{font-weight:600;font-size:13px;color:#2b6cb0}
.time{font-size:12px;color:#9aa7b8}
.card-b{font-size:13px;line-height:1.6;color:#334155;word-break:break-word;white-space:pre-wrap}
.empty{text-align:center;color:#9aa7b8;font-size:13px;padding:26px 0}
.msg{display:none;font-size:13px;padding:9px 12px;border-radius:8px;margin-bottom:10px}
.msg.ok{display:block;background:#e6f7ec;color:#1c7c43;border:1px solid #bde9cd}
.msg.err{display:block;background:#fdecec;color:#b02a2a;border:1px solid #f5c6c6}
</style></head><body><div class="wrap">
<div class="head"><h1>MC 离线启动器 · 反馈中心</h1><p>所有访客的反馈都会展示在这里，也可以提交你自己的反馈</p></div>
<div class="panel">
<h2>提交反馈</h2>
<div class="msg" id="msg"></div>
<div class="row"><input id="fname" maxlength="16" placeholder="你的昵称（可选）"></div>
<textarea id="ftext" maxlength="500" placeholder="想说的话、建议、遇到的 bug…"></textarea>
<button class="btn" id="fbtn" onclick="submitFb()">提交反馈</button>
<div class="tip">提交后所有访客都能看到；同一 IP 每分钟限 1 条</div>
</div>
<div class="panel"><h2>全部反馈</h2>__CARDS__</div>
</div>
<script>
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function submitFb(){
  var n=document.getElementById('fname').value.trim();
  var t=document.getElementById('ftext').value.trim();
  var m=document.getElementById('msg');
  if(!t){m.className='msg err';m.textContent='请填写反馈内容';return;}
  document.getElementById('fbtn').disabled=true;
  fetch('/api/feedback',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'name='+encodeURIComponent(n)+'&text='+encodeURIComponent(t)})
  .then(function(r){return r.json();})
  .then(function(j){
    if(j.ok){m.className='msg ok';m.textContent=j.msg;document.getElementById('ftext').value='';setTimeout(function(){location.reload();},800);}
    else{m.className='msg err';m.textContent=j.msg;document.getElementById('fbtn').disabled=false;}
  })
  .catch(function(){m.className='msg err';m.textContent='网络错误，请稍后再试';document.getElementById('fbtn').disabled=false;});
}
</script></body></html>'''


@app.route('/feedback')
def feedback_page():
    return _fb_page()


@app.route('/api/feedback', methods=['GET', 'POST'])
def api_feedback():
    p = _unpack()
    name = (p.get('name') or '').strip()[:16]
    text = (p.get('text') or '').strip()[:500]
    if not text:
        return _out({'ok': False, 'msg': '请填写反馈内容'}, 400)
    if not name:
        name = '匿名'
    ip = _pubip()
    now = time.time()
    if ip in _fb_recent and now - _fb_recent[ip] < 60:
        return _out({'ok': False, 'msg': '提交太频繁，请 1 分钟后再试'}, 429)
    _fb_recent[ip] = now
    _fb_append({'ts': now, 'name': name, 'text': text})
    return _out({'ok': True, 'msg': '反馈已提交，感谢！'})


@app.route('/api/feedback/list', methods=['GET'])
def api_feedback_list():
    items = _fb_load()
    return jsonify(ok=True, count=len(items), items=[
        {'name': x.get('name'), 'time': x.get('ts'), 'text': x.get('text')}
        for x in items[-50:]
    ])


# 清理过期房间/网络（每次请求时惰性清理）
@app.before_request
def _gc():
    now = time.time()
    dead = [k for k, v in rooms.items() if now - v['ts'] > TTL]
    for k in dead:
        rooms.pop(k, None)
    deadn = [k for k, v in networks.items() if now - v['ts'] > NET_TTL]
    for k in deadn:
        networks.pop(k, None)
