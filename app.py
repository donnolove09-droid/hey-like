from flask import Flask, request, jsonify, make_response
import asyncio

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii, aiohttp, requests, json
import like_pb2, like_count_pb2, uid_generator_pb2
import time, random, os, jwt, threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== CREDITS =====
CHANNEL = "@DGDRIFT"
CREDIT  = "@DG_DRIFT"
GROUP   = "@driftautolike"

TOKEN_CACHE = {}
app = Flask(__name__)

KEY_LIMIT = 10000
tracker = defaultdict(lambda: [0, time.time()])
liked_cache = defaultdict(set)

# ===== TOKEN FILES (per server) =====
TOKEN_FILES = {
    "IND": "token_ind.json",
    "BR":  "token_br.json",
    "BD":  "token_bd.json",
    "RU":  "token_ru.json",
    "VN":  "token_vn.json",
}
ACCOUNT_FILES = {
    "IND": "account_ind.txt",
    "BR":  "account_br.txt",
    "BD":  "account_bd.txt",
    "RU":  "account_ru.txt",
    "VN":  "account_vn.txt",
}

# ===== ALL SERVER URLS =====
URLS = {
    "IND": "https://client.ind.freefiremobile.com",
    "BR":  "https://client.us.freefiremobile.com",
    "US":  "https://client.us.freefiremobile.com",
    "SAC": "https://client.us.freefiremobile.com",
    "NA":  "https://client.us.freefiremobile.com",
    "BD":  "https://clientbp.ppmainecoonghj.com",
    "VN":  "https://clientbp.ppmainecoonghj.com",
    "RU":  "https://client.ru.freefiremobile.com",
}

JWT_API = "https://jwt-ob55-api.onrender.com/token"

UA = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
XGA_SV = "1789556611"
UNITY_V = "2018.4.12f1"
REL_V = "OB55"

# ===== SPEED & SCHEDULE TUNING =====
JWT_CONCURRENCY     = 50
LIKE_CONCURRENCY    = 50
JWT_TIMEOUT         = 30

# ⏰ Token JWT ~8h me expire hota hai
# Har 30 min check karega, agar token expire hone wala hai to refresh karega
CHECK_INTERVAL_MIN  = 30      # check every 30 minutes
TOKEN_MIN_VALIDITY  = 1800    # 30 min — isse kam bacha to refresh karo

def midnight():
    n = datetime.now()
    return datetime(n.year, n.month, n.day).timestamp()

def is_placeholder(u, p):
    bad = {"uid", "password", "user", "pass", "your_uid", "your_password"}
    return u.lower() in bad or p.lower() in bad

def load_file(fn):
    accs = []
    seen = set()
    if not os.path.exists(fn):
        return accs
    try:
        with open(fn) as f:
            for l in f:
                l = l.strip()
                if not l or l.startswith('#'):
                    continue
                if ':' in l:
                    u, p = l.split(':', 1)
                    u, p = u.strip(), p.strip()
                    if not u or not p or is_placeholder(u, p):
                        continue
                    if u not in seen:
                        seen.add(u)
                        accs.append({"uid": u, "password": p})
    except Exception:
        pass
    return accs

def load_accounts(s):
    if s in {"BR","US","SAC","NA"}:
        primary = "account_br.txt"
    elif s == "IND":
        primary = "account_ind.txt"
    elif s == "BD":
        primary = "account_bd.txt"
    elif s == "VN":
        primary = "account_vn.txt"
    elif s == "RU":
        primary = "account_ru.txt"
    else:
        primary = "account_ind.txt"
    a = load_file(primary)
    if a:
        print(f"Loaded {len(a)} accounts from {primary} for {s}")
        return a
    # Fallback: VN có thể dùng chung account BD (cùng cluster SEA)
    fallbacks = ["account_ind.txt", "account_br.txt", "account_bd.txt", "account_ru.txt", "account_vn.txt"]
    if s == "VN":
        fallbacks = ["account_bd.txt", "account_vn.txt", "account_ind.txt", "account_br.txt", "account_ru.txt"]
    for fb in fallbacks:
        if fb == primary:
            continue
        a = load_file(fb)
        if a:
            print(f"⚠️ Fallback: loaded {len(a)} accounts from {fb} for {s}")
            return a
    return []


def load_accounts_by_file():
    result = {}
    for srv, fn in ACCOUNT_FILES.items():
        a = load_file(fn)
        if a:
            result[srv] = a
    return result

# ===== TOKEN FILE SAVE / LOAD =====
def save_tokens_for_server(server, uids):
    fname = TOKEN_FILES.get(server)
    if not fname:
        return False
    try:
        tokens = {}
        for uid in uids:
            c = TOKEN_CACHE.get(uid)
            if not c:
                continue
            tokens[uid] = {
                "token": c.get("token"),
                "expires_at": c["expires_at"].isoformat() if isinstance(c.get("expires_at"), datetime) else str(c.get("expires_at")),
                "login_url": c.get("login_url"),
                "region": c.get("region"),
                "fetched_at": c.get("fetched_at"),
            }
        data = {
            "server": server,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(tokens),
            "tokens": tokens,
        }
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
        print(f"💾 Saved {len(tokens)} tokens → {fname}")
        return True
    except Exception as e:
        print(f"⚠️ Failed to save {fname}: {e}")
        return False

def load_tokens_from_file(server):
    fname = TOKEN_FILES.get(server)
    if not fname or not os.path.exists(fname):
        return 0
    try:
        with open(fname) as f:
            data = json.load(f)
        now = datetime.now(timezone.utc)
        loaded = 0
        skipped = 0
        for uid, c in (data.get("tokens") or {}).items():
            try:
                exp = datetime.fromisoformat(c["expires_at"])
                if (exp - now).total_seconds() > TOKEN_MIN_VALIDITY:
                    TOKEN_CACHE[uid] = {
                        "token": c["token"],
                        "expires_at": exp,
                        "login_url": c.get("login_url"),
                        "region": c.get("region"),
                        "fetched_at": c.get("fetched_at", time.time()),
                    }
                    loaded += 1
                else:
                    skipped += 1
            except Exception:
                continue
        print(f"📂 Loaded {loaded} tokens from {fname} (skipped {skipped} expired)")
        return loaded
    except Exception as e:
        print(f"⚠️ Failed to load {fname}: {e}")
        return 0

def load_all_tokens_from_files():
    total = 0
    for srv in TOKEN_FILES.keys():
        total += load_tokens_from_file(srv)
    return total

async def fetch_raw(session, uid, pwd):
    try:
        url = f"{JWT_API}?uid={uid}&password={pwd}"
        async with session.get(url, timeout=JWT_TIMEOUT) as r:
            if r.status != 200:
                return None
            d = await r.json()
            if not isinstance(d, dict) or not d.get("Success", True):
                return None
            return d
    except Exception:
        return None

def token_is_valid(uid):
    """Check if cached token is still valid (with buffer)"""
    c = TOKEN_CACHE.get(uid)
    if not c:
        return False
    try:
        remaining = (c["expires_at"] - datetime.now(timezone.utc)).total_seconds()
        return remaining > TOKEN_MIN_VALIDITY
    except Exception:
        return False

def token_time_left(uid):
    """Seconds left before expiry (negative if expired)"""
    c = TOKEN_CACHE.get(uid)
    if not c:
        return -1
    try:
        return (c["expires_at"] - datetime.now(timezone.utc)).total_seconds()
    except Exception:
        return -1

async def get_valid_token(session, uid, pwd, force=False):
    """Returns cached token if valid, else fetches new"""
    if not force and token_is_valid(uid):
        return TOKEN_CACHE[uid]["token"]

    d = await fetch_raw(session, uid, pwd)
    if not d:
        return None
    t = d.get("Jwt_Token") or d.get("jwt_token") or d.get("token")
    if not t or t == "N/A":
        return None
    try:
        p = jwt.decode(t, options={"verify_signature": False})
        exp = datetime.fromtimestamp(p["exp"], tz=timezone.utc)
    except Exception:
        exp = datetime.now(timezone.utc) + timedelta(hours=8)
    TOKEN_CACHE[uid] = {
        "token": t,
        "expires_at": exp,
        "login_url": d.get("Login_url"),
        "region": d.get("Region"),
        "fetched_at": time.time(),
    }
    return t

def encrypt_msg(pt):
    c = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    return binascii.hexlify(c.encrypt(pad(pt, AES.block_size))).decode()

def make_pb(uid, region):
    m = like_pb2.like()
    m.uid = int(uid)
    m.region = region
    return m.SerializeToString()

async def send_like(session, enc_uid, token, url):
    try:
        h = {
            'User-Agent': UA, 'Accept': "*/*", 'Accept-Encoding': "deflate, gzip",
            'X-GA-SV': XGA_SV, 'Authorization': f"Bearer {token}", 'X-GA': "v1 1",
            'ReleaseVersion': REL_V, 'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': UNITY_V
        }
        async with session.post(url, data=bytes.fromhex(enc_uid), headers=h, timeout=10) as r:
            return r.status
    except Exception:
        return 500

def region_of(login_url, region_field):
    if region_field:
        r = str(region_field).upper()
        if r in URLS:
            return r
    if not login_url:
        return None
    l = login_url.lower()
    if "client.ind" in l: return "IND"
    if "client.us" in l: return "US"
    if "client.ru" in l: return "RU"
    if "clientbp" in l or "client.bd" in l or "client.vn" in l: return "BD"  # VN & BD cùng cluster SEA
    return None

def region_matches(acc_region, target):
    if not acc_region:
        return True
    if target == "IND": return acc_region == "IND"
    if target in {"BD", "VN"}: return acc_region in {"BD", "VN"}  # VN & BD dùng chung
    if target == "RU": return acc_region == "RU"
    if target in {"BR","US","SAC","NA"}: return acc_region in {"BR","US","SAC","NA"}
    return True


# ===== SMART PREWARM =====
async def prewarm_tokens(accs, server=None, force=False):
    need_fetch = []
    already_valid = []
    for a in accs:
        if not force and token_is_valid(a['uid']):
            already_valid.append(a)
        else:
            need_fetch.append(a)

    tag = server or "ALL"
    print(f"🔎 Prewarm[{tag}]: {len(already_valid)} cached valid, {len(need_fetch)} need fetch")

    valid_fetched = []
    if need_fetch:
        sem = asyncio.Semaphore(JWT_CONCURRENCY)
        connector = aiohttp.TCPConnector(limit=JWT_CONCURRENCY * 2, force_close=False)
        timeout = aiohttp.ClientTimeout(total=JWT_TIMEOUT)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async def one(a):
                async with sem:
                    t = await get_valid_token(session, a['uid'], a['password'], force=force)
                    if not t:
                        return None
                    return a
            results = await asyncio.gather(*[one(a) for a in need_fetch], return_exceptions=True)
        valid_fetched = [r for r in results if isinstance(r, dict)]

    combined = already_valid + valid_fetched

    if server is not None:
        filtered = []
        for a in combined:
            c = TOKEN_CACHE.get(a['uid']) or {}
            if region_matches(region_of(c.get("login_url"), c.get("region")), server):
                filtered.append(a)
        combined = filtered

    print(f"✅ Prewarm[{tag}]: {len(combined)}/{len(accs)} valid")
    return combined

# ===== PARALLEL LIKE BLAST =====
async def broadcast_likes(target, server, url, valid_accs):
    pb = make_pb(target, server)
    enc_uid = encrypt_msg(pb)
    done = liked_cache.get(target, set())
    fresh = [a for a in valid_accs if a['uid'] not in done]
    if not fresh:
        return {"success": 0, "failed": 0}
    random.shuffle(fresh)
    sem = asyncio.Semaphore(LIKE_CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=LIKE_CONCURRENCY * 2, force_close=False)
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async def one(a):
            async with sem:
                c = TOKEN_CACHE.get(a['uid']) or {}
                ep = f"{c['login_url'].rstrip('/')}/LikeProfile" if c.get("login_url") else url
                tok = c.get("token")
                if not tok:
                    return 500
                st = await send_like(session, enc_uid, tok, ep)
                if st == 200:
                    liked_cache[target].add(a['uid'])
                return st
        results = await asyncio.gather(*[one(a) for a in fresh], return_exceptions=True)
    ok = sum(1 for r in results if r == 200)
    return {"success": ok, "failed": len(results) - ok}

def enc(uid):
    m = uid_generator_pb2.uid_generator()
    fs = list(m.DESCRIPTOR.fields)
    setattr(m, fs[0].name, int(uid))
    if len(fs) > 1:
        setattr(m, fs[1].name, 1)
    return encrypt_msg(m.SerializeToString())

def decode(b):
    try:
        i = like_count_pb2.Info()
        i.ParseFromString(b)
        return i
    except Exception:
        return None

def get_info(enc_uid, server, token):
    url = URLS.get(server, URLS["IND"])
    h = {
        'User-Agent': UA, 'Accept': "*/*", 'Accept-Encoding': "deflate, gzip",
        'X-GA-SV': XGA_SV, 'Authorization': f"Bearer {token}", 'X-GA': "v1 1",
        'ReleaseVersion': REL_V, 'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': UNITY_V
    }
    try:
        r = requests.post(f"{url}/GetPlayerPersonalShow", data=bytes.fromhex(enc_uid), headers=h, verify=False, timeout=10)
        return decode(r.content)
    except Exception:
        return None

# ===== SMART REFRESH — ONLY EXPIRED / ABOUT-TO-EXPIRE =====
def refresh_expired_tokens():
    """
    Scan all account files.
    Only refetch tokens that:
      - are missing from cache, OR
      - will expire within TOKEN_MIN_VALIDITY (30 min)
    """
    grouped = load_accounts_by_file()
    if not grouped:
        print("⚠️ No account files found")
        return 0

    total_refreshed = 0
    for srv, accs in grouped.items():
        expired = [a for a in accs if not token_is_valid(a['uid'])]
        if not expired:
            print(f"✅ {srv}: all {len(accs)} tokens valid — skip")
            continue

        # show how many are truly expired vs about-to-expire
        truly_expired = [a for a in expired if token_time_left(a['uid']) <= 0]
        near_expiry   = [a for a in expired if 0 < token_time_left(a['uid']) <= TOKEN_MIN_VALIDITY]
        print(f"🔄 {srv}: {len(truly_expired)} expired, {len(near_expiry)} expiring soon — refreshing {len(expired)}")

        t0 = time.time()
        valid = asyncio.run(prewarm_tokens(expired, server=None, force=False))
        dt = round(time.time() - t0, 2)
        print(f"✅ {srv} refreshed — {len(valid)}/{len(expired)} valid in {dt}s")

        uids = [a['uid'] for a in accs if a['uid'] in TOKEN_CACHE]
        save_tokens_for_server(srv, uids)
        total_refreshed += len(valid)
    return total_refreshed

def scheduler_loop():
    """
    Background loop:
      1. Load saved tokens from JSON files (skip expired)
      2. Initial fetch if nothing valid
      3. Every CHECK_INTERVAL_MIN minutes, check for expired tokens & refresh them
    """
    loaded = load_all_tokens_from_files()
    print(f"📂 Total loaded from files: {loaded}")

    if loaded == 0:
        print("⚠️ No cached tokens — initial fetch needed")
        try:
            refresh_expired_tokens()
        except Exception as e:
            print(f"⚠️ Initial fetch failed: {e}")

    while True:
        time.sleep(CHECK_INTERVAL_MIN * 60)
        try:
            print(f"⏰ {CHECK_INTERVAL_MIN}min check — scanning for expired tokens...")
            refresh_expired_tokens()
        except Exception as e:
            print(f"⚠️ Scheduled check failed: {e}")

# ===== ROUTES =====
@app.route('/')
def index():
    html = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Free Fire Like API · OB55</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:'Inter',system-ui,sans-serif;
    background:#0a0a0f;
    color:#e4e4e7;
    min-height:100vh;
    background-image:
      radial-gradient(ellipse 80% 50% at 50% -20%, rgba(120,40,200,.25), transparent),
      radial-gradient(ellipse 60% 40% at 80% 50%, rgba(0,150,255,.08), transparent);
  }
  .wrap{max-width:720px;margin:0 auto;padding:40px 20px 60px}
  .badge{
    display:inline-flex;align-items:center;gap:6px;
    background:rgba(139,92,246,.15);border:1px solid rgba(139,92,246,.3);
    color:#c4b5fd;font-size:12px;font-weight:600;
    padding:5px 12px;border-radius:99px;margin-bottom:16px;
  }
  h1{
    font-size:clamp(28px,6vw,40px);font-weight:800;
    background:linear-gradient(135deg,#fff 0%,#a78bfa 50%,#60a5fa 100%);
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    letter-spacing:-.02em;margin-bottom:8px;
  }
  .sub{color:#71717a;font-size:15px;margin-bottom:36px;line-height:1.5}
  .card{
    background:rgba(24,24,27,.8);border:1px solid rgba(63,63,70,.6);
    border-radius:16px;padding:24px;margin-bottom:20px;
    backdrop-filter:blur(12px);
  }
  .card h2{font-size:15px;font-weight:700;color:#a1a1aa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:16px}
  .endpoint{
    background:#18181b;border:1px solid #27272a;border-radius:10px;
    padding:14px 16px;font-family:ui-monospace,monospace;font-size:13px;
    color:#a78bfa;word-break:break-all;margin-bottom:12px;line-height:1.5;
  }
  .params{width:100%;border-collapse:collapse;font-size:13px}
  .params th{text-align:left;color:#71717a;font-weight:600;padding:8px 10px;border-bottom:1px solid #27272a}
  .params td{padding:10px;border-bottom:1px solid #1f1f23}
  .params tr:last-child td{border-bottom:none}
  .tag{display:inline-block;background:rgba(34,197,94,.12);color:#4ade80;font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px}
  .tag.opt{background:rgba(251,191,36,.12);color:#fbbf24}
  .servers{display:flex;flex-wrap:wrap;gap:8px}
  .srv{
    background:rgba(99,102,241,.12);border:1px solid rgba(99,102,241,.25);
    color:#a5b4fc;font-size:13px;font-weight:600;
    padding:6px 14px;border-radius:8px;
  }
  .srv.vn{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.3);color:#fca5a5}
  .ex{background:#0f0f12;border:1px solid #27272a;border-radius:10px;padding:12px 14px;margin-top:10px}
  .ex a{color:#60a5fa;text-decoration:none;font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-all}
  .ex a:hover{text-decoration:underline}
  .status{display:flex;align-items:center;gap:8px;font-size:13px;color:#4ade80;margin-top:8px}
  .dot{width:8px;height:8px;background:#22c55e;border-radius:50%;box-shadow:0 0 8px #22c55e}
  footer{text-align:center;margin-top:40px;color:#52525b;font-size:12px}
  footer a{color:#71717a;text-decoration:none}
</style>
</head>
<body>
<div class="wrap">
  <div class="badge">🔥 Free Fire · OB55</div>
  <h1>Like API</h1>
  <p class="sub">API tăng like Free Fire nhanh · Hỗ trợ nhiều server · Không cần đăng nhập</p>

  <div class="card">
    <h2>Endpoint Like</h2>
    <div class="endpoint">GET /like?uid={UID}&amp;server_name={SERVER}&amp;key=SAMIR</div>
    <table class="params">
      <tr><th>Tham số</th><th>Bắt buộc</th><th>Mô tả</th></tr>
      <tr><td><code>uid</code></td><td><span class="tag">Có</span></td><td>UID người chơi cần like</td></tr>
      <tr><td><code>server_name</code></td><td><span class="tag">Có</span></td><td>Server: IND, BR, BD, VN, RU...</td></tr>
      <tr><td><code>key</code></td><td><span class="tag">Có</span></td><td>API key = <b>SAMIR</b></td></tr>
    </table>
    <div class="ex">
      <a href="/like?uid=123456789&amp;server_name=VN&amp;key=SAMIR" target="_blank">
        /like?uid=123456789&amp;server_name=VN&amp;key=SAMIR
      </a>
    </div>
  </div>

  <div class="card">
    <h2>Server hỗ trợ</h2>
    <div class="servers">
      <span class="srv vn">VN 🇻🇳</span>
      <span class="srv">IND 🇮🇳</span>
      <span class="srv">BR 🇧🇷</span>
      <span class="srv">US 🇺🇸</span>
      <span class="srv">BD 🇧🇩</span>
      <span class="srv">RU 🇷🇺</span>
      <span class="srv">SAC</span>
      <span class="srv">NA</span>
    </div>
  </div>

  <div class="card">
    <h2>Reset Limit</h2>
    <div class="endpoint">GET /reset-limit?key=DRIFT</div>
    <p style="font-size:13px;color:#a1a1aa;margin-top:8px">Giới hạn 10.000 lượt/IP/ngày. Dùng key <b>DRIFT</b> để reset.</p>
  </div>

  <div class="card">
    <h2>Trạng thái</h2>
    <div class="status"><span class="dot"></span> API đang hoạt động</div>
  </div>

  <footer>
    Free Fire Like API · OB55<br>
    <span style="opacity:.6">Powered by Render</span>
  </footer>
</div>
</body>
</html>"""
    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp

@app.route('/like')
def like():
    uid = request.args.get("uid")
    server = request.args.get("server_name", "").upper()
    key = request.args.get("key")
    ip = request.remote_addr


    if key != "SAMIR":
        return jsonify({"error": "Invalid API key"}), 403
    if not uid or not server:
        return jsonify({"error": "UID and server_name required"}), 400
    if server not in URLS:
        return jsonify({"error": f"Invalid server. Use: {list(URLS.keys())}"}), 400

    accs = load_accounts(server)
    if not accs:
        return jsonify({"error": f"No accounts available for {server}"}), 500

    mid = midnight()
    cnt, lr = tracker[ip]
    if lr < mid:
        tracker[ip] = [0, time.time()]
        cnt = 0
    if cnt >= KEY_LIMIT:
        return jsonify({"error": "Daily limit reached", "remains": f"(0/{KEY_LIMIT})"}), 429

    t0 = time.time()

    # Smart prewarm: only fetches missing/expired tokens
    valid_accs = asyncio.run(prewarm_tokens(accs, server=server, force=False))
    if not valid_accs:
        return jsonify({"error": f"No valid {server} accounts"}), 500

    tok = TOKEN_CACHE[valid_accs[0]['uid']]['token']
    enc_uid = enc(uid)

    b = get_info(enc_uid, server, tok)
    if b is None:
        return jsonify({"error": "Invalid UID or server mismatch", "status": 0}), 200
    try:
        bd = json.loads(MessageToJson(b))
        bl = int(bd['AccountInfo'].get('Likes', 0))
    except Exception:
        return jsonify({"error": "Parse failed", "status": 0}), 200

    like_url = f"{URLS[server]}/LikeProfile"
    stats = asyncio.run(broadcast_likes(uid, server, like_url, valid_accs))

    a = get_info(enc_uid, server, tok)
    if a is None:
        return jsonify({"error": "Verify failed", "status": 0}), 200
    try:
        ad = json.loads(MessageToJson(a))
        al = int(ad['AccountInfo']['Likes'])
        pid = int(ad['AccountInfo']['UID'])
        pn = str(ad['AccountInfo']['PlayerNickname'])
        given = al - bl
        st = 1 if given != 0 else 2
        if given > 0:
            tracker[ip][0] += 1
            cnt += 1
        return jsonify({
            "LikesGivenByAPI": given,
            "LikesafterCommand": al,
            "LikesbeforeCommand": bl,
            "PlayerNickname": pn,
            "Server": server,
            "UID": pid,
            "status": st,
            "Elapsed sec": round(time.time() - t0, 2),
            "tokens_used": stats.get("success", 0),
            "remains": f"({KEY_LIMIT - cnt}/{KEY_LIMIT})"
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500

@app.route('/reset-limit')
def reset_limit():
    if request.args.get("key") != "DRIFT":
        return jsonify({"error": "Invalid key"}), 403
    ip = request.remote_addr
    tracker[ip] = [0, time.time()]
    return jsonify({
        "message": "Limit reset",
        "ip": ip,
        "remains": f"({KEY_LIMIT}/{KEY_LIMIT})"
    })

# Start background token scheduler (works with both local run and gunicorn on Render)
print("Server starting")
print(f"Supported servers: {list(URLS.keys())}")
print(f"Speed: JWT={JWT_CONCURRENCY}x, LIKE={LIKE_CONCURRENCY}x")
print(f"Token check: every {CHECK_INTERVAL_MIN} min (only expired refreshes)")
print(f"Token files: {list(TOKEN_FILES.values())}")
threading.Thread(target=scheduler_loop, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False)
