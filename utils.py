
import base64
from typing import Optional, Tuple
from flask import request
from config import SESSIONS, USERS, MLS_LEVEL, ACCESS_MATRIX
import time
import secrets

# =========================================================
# UI THEME (Cyber / Terminal) - เพิ่มการตกแต่ง ไม่ยุ่งกับ logic
# =========================================================
THEME_CSS = """
<style>
:root{
  --bg0:#06080f; --bg1:#0b1221; --card:#0b1324cc;
  --line:#00ffd533; --text:#d6ffe8; --muted:#89a7a0;
  --neon:#00ffd5; --pink:#ff3dd8; --warn:#ffd500;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; color:var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;
  background:
    radial-gradient(1000px 600px at 20% 10%, #132a33 0%, transparent 60%),
    radial-gradient(900px 500px at 80% 20%, #2b1244 0%, transparent 55%),
    radial-gradient(900px 600px at 50% 90%, #0a2e1c 0%, transparent 55%),
    linear-gradient(180deg, var(--bg0), var(--bg1));
  overflow-x:hidden;
}
a{color:var(--neon); text-decoration:none}
a:hover{filter:brightness(1.2)}
.container{max-width:980px; margin:0 auto; padding:28px 16px 60px}
.topbar{
  display:flex; align-items:center; justify-content:space-between; gap:12px;
  padding:14px 16px; border:1px solid var(--line);
  background:linear-gradient(180deg, #0b1324cc, #070a12cc);
  border-radius:16px; box-shadow:0 0 0 1px #00ffd511 inset, 0 0 30px #00ffd508;
}
.brand{display:flex; flex-direction:column; gap:4px}
.brand b{letter-spacing:.8px}
.badges{display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end}
.badge{
  font-size:12px; padding:6px 10px; border-radius:999px;
  border:1px solid var(--line); background:#07101dcc;
  color:var(--muted);
}
.badge.neon{color:var(--neon); border-color:#00ffd566}
.badge.pink{color:var(--pink); border-color:#ff3dd866}
.badge.warn{color:var(--warn); border-color:#ffd50066}
.grid{display:grid; grid-template-columns:repeat(12,1fr); gap:14px; margin-top:16px}
.card{
  grid-column:span 12;
  border:1px solid var(--line);
  background:var(--card);
  border-radius:16px;
  padding:16px 16px;
  box-shadow:0 0 0 1px #00ffd50c inset;
}
@media (min-width:840px){
  .card.half{grid-column:span 6}
}
h1,h2,h3,h4{margin:0 0 10px}
h1{font-size:22px}
h2{font-size:18px; color:#bfffee}
h3{font-size:16px; color:#bfffee}
h4{font-size:14px; color:#bfffee; margin-top:14px}
p{margin:8px 0; color:var(--text)}
small, .muted{color:var(--muted)}
hr{border:none; border-top:1px solid var(--line); margin:14px 0}
pre{
  white-space:pre-wrap; word-break:break-word;
  background:#050a14; border:1px solid #00ffd522;
  padding:12px; border-radius:12px; color:#d9fff0;
  box-shadow:0 0 0 1px #00ffd50a inset;
}
.kbd{
  display:inline-block; padding:2px 8px; border-radius:8px;
  border:1px solid #00ffd522; background:#050a14; color:#bfffee;
}
.btn{
  display:inline-flex; align-items:center; gap:8px;
  padding:10px 12px; border-radius:12px;
  border:1px solid #00ffd566; background:#04121a;
  color:var(--neon); cursor:pointer;
  box-shadow:0 0 0 1px #00ffd516 inset, 0 10px 24px #00ffd506;
}
.btn:hover{filter:brightness(1.15)}
.btn.secondary{border-color:#ffffff22; color:#d6ffe8}
.btn.pink{border-color:#ff3dd866; color:#ffb7f1; box-shadow:0 0 0 1px #ff3dd816 inset, 0 10px 24px #ff3dd806}
.row{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
form{display:grid; gap:10px; margin-top:10px}
input{
  width:100%;
  padding:10px 12px; border-radius:12px;
  background:#050a14; border:1px solid #00ffd522; color:var(--text);
}
input:focus{outline:none; border-color:#00ffd588; box-shadow:0 0 0 3px #00ffd51a}
.footer{
  margin-top:16px; color:var(--muted); font-size:12px;
  border-top:1px dashed #00ffd522; padding-top:12px;
}
details{border:1px dashed #00ffd533; border-radius:12px; padding:10px 12px; background:#050a14}
summary{cursor:pointer; color:#bfffee}
.scanline{
  position:fixed; left:0; top:-40%;
  width:100%; height:40%;
  background:linear-gradient(180deg, transparent, #00ffd51a, transparent);
  animation:scan 5.5s linear infinite;
  pointer-events:none;
}
@keyframes scan {0%{top:-40%} 100%{top:120%}}
</style>
<div class="scanline"></div>
"""

THEME_JS = """
<script>
function copyText(id){
  const el = document.getElementById(id);
  if(!el) return;
  const text = el.innerText || el.textContent || "";
  navigator.clipboard.writeText(text).then(()=>{
    const b = document.getElementById(id+"-btn");
    if(b){ b.innerText = "Copied ✓"; setTimeout(()=>b.innerText="Copy", 1100); }
  });
}
</script>
"""

def render_page(title: str, body_html: str, subtitle: str = "") -> str:
    subtitle_html = f"<div class='muted'>{subtitle}</div>" if subtitle else ""
    return f"""
    <!doctype html>
    <html lang="th">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>{title}</title>
      {THEME_CSS}
      {THEME_JS}
    </head>
    <body>
      <div class="container">
        <div class="topbar">
          <div class="brand">
            <b>🛡️ The SUT Secret Server</b>
            {subtitle_html}
          </div>
          <div class="badges">
            <span class="badge neon">CTF MODE</span>
            <span class="badge pink">Crypto → AuthN → AuthZ</span>
            <span class="badge warn">Localhost Only</span>
          </div>
        </div>
        {body_html}
        <div class="footer">
          <div>⚙️ Tip: ดู source / จับ request / คิดเป็นระบบ (Threat Model) — นี่คือวิชา Cyber Security Fundamentals</div>
        </div>
      </div>
    </body>
    </html>
    """

# =========================================================
# UTIL: Base64URL
# =========================================================
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# =========================================================
# SESSION HELPERS
# =========================================================
def new_session(username: str) -> str:
    sid = secrets.token_urlsafe(24)
    profile = USERS.get(username, {})
    SESSIONS[sid] = {
        "sub": username,
        "role": profile.get("role", "guest"),
        "dept": profile.get("dept", "UNKNOWN"),
        "clearance": profile.get("clearance", "PUBLIC"),
        "ts": int(time.time()),
    }
    return sid

def get_session() -> Optional[dict]:
    sid = request.cookies.get("sid")
    if not sid:
        return None
    return SESSIONS.get(sid)

def require_session() -> Tuple[Optional[dict], Optional[Tuple[dict, int]]]:
    sess = get_session()
    if not sess:
        return None, ({"ok": False, "error": "Not logged in (Stage 2 first)."}, 401)
    return sess, None

def is_allowed(role: str, permission: str) -> bool:
    return ACCESS_MATRIX.get(role, {}).get(permission, False)

def clearance_at_least(user_clearance: str, need: str) -> bool:
    return MLS_LEVEL.get(user_clearance, -1) >= MLS_LEVEL.get(need, 999)
