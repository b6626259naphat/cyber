
import json
import time
import hmac
import hashlib
from io import BytesIO
import qrcode
from flask import request, make_response, send_file, Blueprint

from config import (
    STAGE2_PASSWORD_PLAINTEXT, STAGE2_GATE_TTL_SECONDS, STAGE2_GATE_KEY,
    OTP_WINDOW_SECONDS, USERS
)
from utils import render_page, b64url_encode, b64url_decode, new_session

from . import stage2_bp

# =========================================================
# STAGE 2 LOGIC
# =========================================================
def sign_stage2_gate() -> str:
    payload = {"v": 1, "exp": int(time.time()) + STAGE2_GATE_TTL_SECONDS}
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(STAGE2_GATE_KEY, body.encode("utf-8"), hashlib.sha256).digest()
    return f"{body}.{b64url_encode(sig)}"

def verify_stage2_gate(token: str) -> bool:
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(STAGE2_GATE_KEY, body.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(b64url_decode(sig), expected):
            return False
        payload = json.loads(b64url_decode(body).decode("utf-8"))
        return int(payload.get("exp", 0)) >= int(time.time())
    except Exception:
        return False

def has_stage2_gate() -> bool:
    tok = request.cookies.get("s2gate", "")
    return bool(tok) and verify_stage2_gate(tok)

def current_otp_code(seed: str, window: int = OTP_WINDOW_SECONDS) -> str:
    t = int(time.time() // window)
    msg = str(t).encode("utf-8")
    key = seed.encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    num = int.from_bytes(digest[-4:], "big") % 1_000_000
    return f"{num:06d}"

def make_otp_qr_png(seed: str) -> bytes:
    otp = current_otp_code(seed)
    qr_data = {
        "otp": otp,
        "attrs": {
            "location": "SUT-F1",
            "clearance": "SECRET"
        }
    }
    text = json.dumps(qr_data, separators=(",", ":"))
    img = qrcode.make(text)
    bio = BytesIO()
    img.save(bio, format="PNG")
    return bio.getvalue()


# =========================================================
# ROUTES
# =========================================================

@stage2_bp.post('/stage2/unlock')
def unlock():
    password = request.form.get("password", "").strip()

    if password != STAGE2_PASSWORD_PLAINTEXT:
        return render_page(
            "Stage 2 — Locked",
            """
            <div class="grid">
              <div class="card">
                <h1>⛔ Unlock Failed</h1>
                <p class="muted">Password ไม่ถูกต้อง (ต้องเป็นตัวที่ถอดจาก Stage 1)</p>
                <div class="row">
                  <a class="btn secondary" href="/stage1">Back to Stage 1</a>
                  <a class="btn" href="/stage2">Try again</a>
                </div>
              </div>
            </div>
            """,
            subtitle="Stage 2 Gate • Password Required"
        ), 403

    token = sign_stage2_gate()
    resp = make_response("", 302)
    resp.headers["Location"] = "/stage2"
    resp.set_cookie("s2gate", token, httponly=True, samesite="Lax")
    return resp

@stage2_bp.get('/stage2')
def index():
    # ✅ ถ้ายังไม่ unlock ให้ล็อกไว้ก่อน
    if not has_stage2_gate():
        body = """
        <div class="grid">
          <div class="card">
            <h1>🚧 Stage 2 — Locked Gate</h1>
            <p class="muted">ต้องถอดรหัสจาก Stage 1 ก่อน แล้วเอา Password มาใส่เพื่อ “เปิดด่าน 2”</p>
            <hr/>
            <div class="row">
              <a class="btn secondary" href="/stage1">Go Stage 1 (Decrypt)</a>
              <a class="btn secondary" href="/">Home</a>
            </div>

            <h4>Unlock with Stage 1 Password</h4>
            <form method="post" action="/stage2/unlock">
              <label>Password (from Stage 1)</label>
              <input name="password" placeholder="paste decrypted password here" />
              <button class="btn" type="submit">Unlock Stage 2</button>
            </form>
            <small class="muted">เมื่อ Unlock สำเร็จ จะได้ cookie <span class="kbd">s2gate</span> (หมดอายุภายใน ~10 นาที)</small>
          </div>
        </div>
        """
        return render_page("Stage 2 — Locked", body, subtitle="MFA Gateway • Stage 1 Password Required"), 401

    # ✅ ผ่าน gate แล้วค่อยโชว์ OTP + ฟอร์ม MFA (ไม่ต้องกรอกรหัสซ้ำ)
    body = """
    <div class="grid">
      <div class="card">
        <h1>🔐 Stage 2 — Multi-Factor Authentication</h1>
        <p class="muted">Gate unlocked ✅ • Factor: OTP (QR / HMAC)</p>
        <hr/>
        <div class="row">
          <a class="btn secondary" href="/stage1">Back to Stage 1</a>
          <a class="btn secondary" href="/stage3/ui">Stage 3 UI</a>
        </div>
      </div>

      <div class="card half">
        <h3>OTP QR</h3>
        <p class="muted">สแกนแล้วจะได้ JSON ที่มี otp + attrs (ใช้ต่อใน Stage 3 ได้)</p>
        <p><img src="/stage2/otp.png" alt="OTP QR" style="width:100%;max-width:320px;border-radius:14px;border:1px solid #00ffd533;"/></p>
        <p class="muted">Tip: ถ้าไม่อยากสแกน ให้คำนวณ OTP ตาม HMAC (ตามที่สอนในวิชา)</p>
      </div>

      <div class="card half">
        <h3>Login Console</h3>
        <form method="post" action="/stage2/login">
          <label>Username</label>
          <input name="username" value="fame" />
          <label>OTP</label>
          <input name="otp" placeholder="6 digits" />
          <button class="btn" type="submit">Authenticate</button>
        </form>
        <small class="muted">เมื่อสำเร็จ ระบบจะสร้าง session cookie <span class="kbd">sid</span></small>
      </div>
    </div>
    """
    return render_page("Stage 2 — Authentication", body, subtitle="MFA Gateway • OTP Required")

@stage2_bp.get('/stage2/otp.png')
def otp_png():
    if not has_stage2_gate():
        return "Stage 2 is locked. Unlock with Stage 1 password first.", 401

    seed = "server-room-sut-2026"
    png = make_otp_qr_png(seed)
    return send_file(BytesIO(png), mimetype="image/png")

@stage2_bp.post('/stage2/login')
def login():
    if not has_stage2_gate():
        return "Stage 2 is locked. Unlock with Stage 1 password first.", 401

    username = request.form.get("username", "").strip()
    otp = request.form.get("otp", "").strip()

    if username not in USERS:
        return "Unknown user.", 400

    seed = "server-room-sut-2026"
    expected = current_otp_code(seed)
    if otp != expected:
        return "OTP invalid.", 403

    sid = new_session(username)
    resp = make_response(render_page(
        "Login success",
        """
        <div class="grid">
          <div class="card">
            <h1>✅ Authentication Success</h1>
            <p class="muted">Session issued. Proceed to Authorization lab.</p>
            <hr/>
            <div class="row">
              <a class="btn" href="/stage3/ui">Go Stage 3 UI</a>
              <a class="btn secondary" href="/stage3">Go Stage 3 (JSON)</a>
              <a class="btn secondary" href="/">Home</a>
            </div>
          </div>
        </div>
        """,
        subtitle="Access Granted • Session Cookie Generated"
    ))
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    # optional: ล้าง gate หลังล็อกอิน (กัน reuse)
    resp.delete_cookie("s2gate")
    return resp
