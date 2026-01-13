
import json
import time
import hmac
import hashlib
import secrets
from urllib.parse import quote
from io import BytesIO
import qrcode
from flask import request, make_response, send_file, Blueprint

from config import (
    STAGE2_PASSWORD_PLAINTEXT, STAGE2_GATE_TTL_SECONDS, STAGE2_GATE_KEY,
    OTP_WINDOW_SECONDS, USERS,
    OTP_WINDOW_SECONDS, USERS,
    STAGE2_PIN_QUESTIONS, SUT_COORDINATES, MAX_DISTANCE_KM, STAGE2_PROGRESS_KEY,
    OTP_WINDOW_SECONDS, USERS,
    STAGE2_PIN_QUESTIONS, SUT_COORDINATES, MAX_DISTANCE_KM, STAGE2_PROGRESS_KEY,
    STAGE2_KEYSTROKE_TARGET_PHRASE, STAGE2_KEYSTROKE_MIN_TIME_MS, STAGE2_KEYSTROKE_MAX_TIME_MS,
    STAGE2_MAGIC_NUMBER
)
from utils import render_page, b64url_encode, b64url_decode, new_session
from . import stage2_bp
import math

# ===== Layer 1: Password Gate =====
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

# ===== Progress Token (track which layers completed) =====
def sign_progress(layers: list) -> str:
    """layers = [1,2,3,4] means completed layers 1-4"""
    payload = {"layers": layers, "exp": int(time.time()) + STAGE2_GATE_TTL_SECONDS}
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(STAGE2_PROGRESS_KEY, body.encode("utf-8"), hashlib.sha256).digest()
    return f"{body}.{b64url_encode(sig)}"

def verify_progress(token: str) -> list:
    """Return list of completed layers, or empty list if invalid"""
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(STAGE2_PROGRESS_KEY, body.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(b64url_decode(sig), expected):
            return []
        payload = json.loads(b64url_decode(body).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return []
        return payload.get("layers", [])
    except Exception:
        return []

def get_progress() -> list:
    tok = request.cookies.get("s2progress", "")
    return verify_progress(tok) if tok else []

def set_progress_cookie(resp, layers: list):
    token = sign_progress(layers)
    resp.set_cookie("s2progress", token, httponly=True, samesite="Lax")

# ===== Layer 2: PIN Challenge (Random Questions) =====
import random

# Store active questions per session
ACTIVE_QUESTIONS = {}  # {session_id: question_index}

def get_random_question():
    """Get a random question from the pool"""
    return random.choice(STAGE2_PIN_QUESTIONS)

def get_question_for_session():
    """Get or create question for current session"""
    # Use gate cookie as session identifier
    gate = request.cookies.get("s2gate", "")
    if not gate:
        return get_random_question()
    
    # Check if we already have a question for this session
    if gate not in ACTIVE_QUESTIONS:
        question = get_random_question()
        ACTIVE_QUESTIONS[gate] = question
    
    return ACTIVE_QUESTIONS[gate]

def verify_pin(pin: str) -> bool:
    """Verify answer against current session's question"""
    question = get_question_for_session()
    return pin.strip() == question["answer"]

# ===== Layer 2: Location Verification =====
def haversine(lat1, lon1, lat2, lon2):
    """Calculate distance (km) between two points using Haversine formula"""
    R = 6371  # Earth radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2) * math.sin(dlat/2) + \
        math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * \
        math.sin(dlon/2) * math.sin(dlon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def verify_location(lat: float, lon: float) -> tuple[bool, float]:
    """Check if location is within range. Returns (is_valid, distance_km)"""
    target_lat, target_lon = SUT_COORDINATES
    dist = haversine(lat, lon, target_lat, target_lon)
    return dist <= MAX_DISTANCE_KM, dist

# ===== Layer 3: Biometric Verification (Keystroke Dynamics) =====
def verify_keystroke(typed_phrase: str, duration_ms: float) -> tuple[bool, str]:
    """
    Verify keystroke dynamics:
    1. Check if phrase matches target.
    2. Check if duration is within human range.
    """
    if typed_phrase != STAGE2_KEYSTROKE_TARGET_PHRASE:
        return False, "Phrase Mismatch"
    
    if duration_ms < STAGE2_KEYSTROKE_MIN_TIME_MS:
        return False, f"Too Fast (Bot? {duration_ms}ms)"
        
    if duration_ms > STAGE2_KEYSTROKE_MAX_TIME_MS:
        return False, f"Too Slow (Timeout? {duration_ms}ms)"
        
    return True, "OK"

# ===== Layer 3: OTP =====
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
    # ... (Gate check) ...
    if not has_stage2_gate():
        # ... (Locked gate UI) ...
        # (This part is inside index function but simplified in replacement due to context limit, 
        #  Use existing gate check logic logic)
        body = """
        <div class="grid">
          <div class="card">
            <h1>🚧 Stage 2 — Locked Gate</h1>
            <p class="muted">ต้องถอดรหัสจาก Stage 1 ก่อน แล้วเอา Password มาใส่เพื่อ "เปิดด่าน 2"</p>
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
            <small class="muted">เมื่อ Unlock สำเร็จ จะได้ cookie <span class="kbd">s2gate</span></small>
          </div>
        </div>
        """
        return render_page("Stage 2 — Locked", body, subtitle="3-Layer MFA • Stage 1 Password Required"), 401

    # ✅ Check progress
    progress = get_progress()
    
    body = f"""
    <div class="grid">
      <div class="card">
        <h1>🔐 Stage 2 — Multi-Layer Authentication</h1>
        <p class="muted">3-Layer MFA System: PIN → Location → OTP</p>
        <hr/>
        <div class="row">
          <span class="badge {'neon' if 1 in progress else ''}">{'✅' if 1 in progress else '🔒'} Layer 1: PIN</span>
          <span class="badge {'neon' if 2 in progress else ''}">{'✅' if 2 in progress else '🔒'} Layer 2: Biometric</span>
          <span class="badge {'neon' if 3 in progress else ''}">{'✅' if 3 in progress else '🔒'} Layer 3: Location</span>
          <span class="badge {'neon' if 4 in progress else ''}">{'✅' if 4 in progress else '🔒'} Layer 4: OTP</span>
        </div>
      </div>

"""

    # Layer 1: PIN Challenge
    if 1 not in progress:
        question = get_question_for_session()
        body += f"""
      <div class="card">
        <h2>🧩 Layer 1 — PIN Challenge</h2>
        <p class="muted">Find the secret PIN to continue.</p>
        <div class="alert">
          <strong>❓ Challenge:</strong>
          <p>{question['question']}</p>
          <small class="muted">{question['hint']}</small>
        </div>
        <form method="post" action="/stage2/layer2">
          <label>Answer (ตัวเลขเท่านั้น)</label>
          <input name="pin" placeholder="ตอบเป็นตัวเลข" />
          <button class="btn" type="submit">Submit Answer</button>
        </form>
      </div>
"""
    # Layer 2: Biometric Verification
    elif 2 not in progress:
        body += f"""
      <div class="card">
        <h2>👤 Layer 2 — Behavioral Biometrics</h2>
        <p class="muted">Keystroke Dynamics Verification</p>
        <div class="alert">
          <strong>⌨️ Typing Challenge:</strong>
          <p>เปิด <code>Developer Console</code> เพื่อดูข้อความลับที่ต้องพิมพ์</p>
          <p class="muted">Tips: Right Click -> Inspect -> Console</p>
          <code style="font-size: 1.2em; color: #00ffd5; display:none;">{STAGE2_KEYSTROKE_TARGET_PHRASE}</code>
        </div>
        
        <form id="bioForm" method="post" action="/stage2/layer_bio" onsubmit="return finalizeTyping()">
          <input type="hidden" name="phrase" id="phraseInput" />
          <input type="hidden" name="duration" id="durationInput" />
          
          <div style="margin: 1.5rem 0;">
              <input type="text" id="typingArea" placeholder="Start typing here..." 
                     autocomplete="off" onpaste="return false;" 
                     style="text-align:center; font-family:monospace; letter-spacing:1px;" />
          </div>
          
          <div style="text-align:center;">
              <button class="btn" type="submit" id="submitBtn" disabled>Verifying...</button>
          </div>
        </form>

        <script>
        // Secret for CTF Player
        console.log("%c[SECRET PHRASE] The phrase is: {STAGE2_KEYSTROKE_TARGET_PHRASE}", "color: #00ffd5; font-size: 16px; font-weight: bold;");
        
        let startTime = 0;
        let endTime = 0;
        let started = false;
        
        const target = "{STAGE2_KEYSTROKE_TARGET_PHRASE}";
        const input = document.getElementById('typingArea');
        const btn = document.getElementById('submitBtn');
        
        input.addEventListener('keydown', (e) => {{
            if (!started) {{
                startTime = performance.now();
                started = true;
            }}
        }});
        
        input.addEventListener('keyup', (e) => {{
            const val = input.value;
            if (val === target) {{
                endTime = performance.now();
                btn.disabled = false;
                btn.textContent = "Submit Analysis";
                btn.style.borderColor = "#00ffd5";
                input.style.borderColor = "#00ffd5";
            }} else {{
                btn.disabled = true;
                btn.textContent = "Processing...";
                input.style.borderColor = "";
            }}
        }});
        
        function finalizeTyping() {{
            if (!startTime || !endTime) return false;
            
            const duration = Math.round(endTime - startTime);
            document.getElementById('phraseInput').value = input.value;
            document.getElementById('durationInput').value = duration;
            return true;
        }}
        </script>
        
      </div>
"""
    # Layer 3: Location Verification
    elif 3 not in progress:
        body += f"""
      <div class="card">
        <h2>📍 Layer 3 — Location Verification</h2>
        <p class="muted">ยืนยันว่าคุณอยู่ในพื้นที่ มหาวิทยาลัยเทคโนโลยีสุรนารี</p>
        <div class="alert">
          <strong>📡 GPS Check:</strong>
          <p>ระบบจะขอเข้าถึงตำแหน่งของคุณเพื่อตรวจสอบว่าอยู่ในรัศมี {MAX_DISTANCE_KM} กม. จาก มทส. หรือไม่</p>
        </div>
        <form id="locForm" method="post" action="/stage2/layer_loc">
          <input type="hidden" name="lat" id="latInput" />
          <input type="hidden" name="lon" id="lonInput" />
          <div id="statusMsg" class="muted" style="margin-bottom:1rem;">Click button to verify location...</div>
          <button class="btn" type="button" onclick="getLocation()">📍 Check My Location</button>
          

        </form>
        
        <script>
        function getLocation() {{
            const status = document.getElementById("statusMsg");
            if (navigator.geolocation) {{
                status.textContent = "⏳ Requesting location access...";
                navigator.geolocation.getCurrentPosition(showPosition, showError);
            }} else {{
                status.textContent = "❌ Geolocation is not supported by this browser.";
            }}
        }}

        function showPosition(position) {{
            document.getElementById("latInput").value = position.coords.latitude;
            document.getElementById("lonInput").value = position.coords.longitude;
            document.getElementById("statusMsg").textContent = "✅ Location acquired! Submitting...";
            document.getElementById("locForm").submit();
        }}

        function showError(error) {{
            switch(error.code) {{
                case error.PERMISSION_DENIED:
                    document.getElementById("statusMsg").textContent = "❌ User denied the request for Geolocation.";
                    break;
                case error.POSITION_UNAVAILABLE:
                    document.getElementById("statusMsg").textContent = "❌ Location information is unavailable.";
                    break;
                case error.TIMEOUT:
                    document.getElementById("statusMsg").textContent = "❌ The request to get user location timed out.";
                    break;
                case error.UNKNOWN_ERROR:
                    document.getElementById("statusMsg").textContent = "❌ An unknown error occurred.";
                    break;
            }}
        }}
        </script>
      </div>
"""
    # Layer 4: OTP (Final)
    elif 4 not in progress:
        body += """
      <div class="card">
        <h2>⏱️ Layer 4 — Time-based OTP (Final)</h2>
        <p class="muted">ขั้นตอนสุดท้าย: ยืนยันด้วย OTP</p>
        
        <!-- Countdown Timer -->
        <div class="alert" id="timer-alert">
          <strong>⏰ เวลาคงเหลือ:</strong>
          <span id="countdown" style="font-size:1.5em;color:#00ffd5;font-weight:bold;">30</span> วินาที
          <p class="muted" id="timer-status">OTP จะเปลี่ยนเมื่อหมดเวลา</p>
        </div>
        
        <div class="row">
          <div class="half">
            <h3>OTP QR Code</h3>
            <p><img id="qr-image" src="/stage2/otp.png?t=0" alt="OTP QR" style="width:100%;max-width:320px;border-radius:14px;border:1px solid #00ffd533;"/></p>
            <p class="muted">สแกนเพื่อดู OTP + attributes</p>
          </div>
          <div class="half">
            <h3>Enter OTP</h3>
            <form method="post" action="/stage2/login">
              <input type="hidden" name="username" value="fame" />
              <label>OTP (6 digits)</label>
              <input name="otp" id="otp-input" placeholder="000000" maxlength="6" autofocus />
              <button class="btn" type="submit">Complete Authentication</button>
            </form>

          </div>
        </div>
      </div>
      
      <script>
        // OTP Timer and Auto-refresh
        const OTP_WINDOW = 30; // seconds
        let timeLeft = OTP_WINDOW;
        let refreshCount = 0;
        
        function updateCountdown() {
          const now = Math.floor(Date.now() / 1000);
          timeLeft = OTP_WINDOW - (now % OTP_WINDOW);
          
          const countdownEl = document.getElementById('countdown');
          const statusEl = document.getElementById('timer-status');
          const alertEl = document.getElementById('timer-alert');
          
          countdownEl.textContent = timeLeft;
          
          // Warning when time is running out
          if (timeLeft <= 5) {
            alertEl.style.borderColor = '#ff6b6b';
            statusEl.textContent = '⚠️ เวลาใกล้หมด! OTP กำลังจะเปลี่ยน';
            statusEl.style.color = '#ff6b6b';
          } else if (timeLeft <= 10) {
            alertEl.style.borderColor = '#ffd93d';
            statusEl.textContent = '⏰ เวลาเหลือน้อย';
            statusEl.style.color = '#ffd93d';
          } else {
            alertEl.style.borderColor = '#00ffd533';
            statusEl.textContent = 'OTP จะเปลี่ยนเมื่อหมดเวลา';
            statusEl.style.color = '';
          }
          
          // Refresh QR when time resets (new window)
          if (timeLeft === OTP_WINDOW) {
            refreshQR();
          }
        }
        
        function refreshQR() {
          const qrImage = document.getElementById('qr-image');
          const timestamp = Date.now();
          qrImage.src = '/stage2/otp.png?t=' + timestamp;
          refreshCount++;
          console.log('QR refreshed:', refreshCount);
        }
        
        // Update every second
        setInterval(updateCountdown, 1000);
        updateCountdown(); // Initial call
      </script>
"""
    else:
        # All layers completed!
        body += """
      <div class="card">
        <h1>✅ All Layers Completed!</h1>
        <p class="muted">คุณผ่านทุกขั้นตอนของ 4-Layer MFA แล้ว</p>
        <div class="row">
          <a class="btn" href="/stage3/ui">Go to Stage 3</a>
          <a class="btn secondary" href="/">Home</a>
        </div>
      </div>
"""

    body += """
    </div>
    """
    resp = make_response(render_page("Stage 2 — 4-Layer MFA", body, subtitle="Advanced Authentication System"))
    # Fix UnicodeEncodeError: Headers must be latin-1. URL encode the value if it has special chars.
    resp.headers["X-SUT-Magic"] = quote(STAGE2_MAGIC_NUMBER)
    return resp

# ===== Layer Handlers =====

@stage2_bp.post('/stage2/layer2')
def layer2_pin():
    if not has_stage2_gate():
        return "Unauthorized", 401
    
    pin = request.form.get("pin", "")
    if not verify_pin(pin):
        return render_page(
            "Layer 2 Failed",
            """
            <div class="grid">
              <div class="card">
                <h1>❌ Answer Incorrect</h1>
                <p class="muted">ลองใหม่อีกครั้ง</p>
                <a class="btn" href="/stage2">Back</a>
              </div>
            </div>
            """,
            subtitle="PIN Challenge Failed"
        ), 403
    
    progress = get_progress()
    if 1 not in progress:
        progress.append(1)
    resp = make_response("", 302)
    resp.headers["Location"] = "/stage2"
    set_progress_cookie(resp, progress)
    return resp

@stage2_bp.post('/stage2/layer_bio')
def layer_bio():
    if not has_stage2_gate():
        return "Unauthorized", 401
    
    progress = get_progress()
    if 1 not in progress:
         return "Complete Layer 1 first", 403

    phrase = request.form.get("phrase", "")
    duration_str = request.form.get("duration", "0")
    
    try:
        duration = float(duration_str)
    except ValueError:
        duration = 0

    is_valid, msg = verify_keystroke(phrase, duration)

    if not is_valid:
        return render_page(
            "Layer 2 Failed",
            f"""
            <div class="grid">
              <div class="card">
                <h1>❌ Keystroke Analysis Failed</h1>
                <p class="muted">Your typing behavior is suspicious.</p>
                <div class="alert">
                   <strong>Analysis Result:</strong>
                   <p class="text-error">{msg}</p>
                   <p>Duration: {duration}ms</p>
                </div>
                <a class="btn" href="/stage2">Try Again</a>
              </div>
            </div>
            """,
            subtitle="Behavioral Biometrics Failed"
        ), 403

    if 2 not in progress:
        progress.append(2)
    resp = make_response("", 302)
    resp.headers["Location"] = "/stage2"
    set_progress_cookie(resp, progress)
    return resp

@stage2_bp.post('/stage2/layer_loc')
def layer3_location():
    if not has_stage2_gate():
        return "Unauthorized", 401
    
    progress = get_progress()
    if 2 not in progress:
        return "Complete Layer 1-2 first", 403
    
    try:
        # Try to get from hidden inputs first, else manual inputs
        lat_str = request.form.get("lat") or request.form.get("manual_lat")
        lon_str = request.form.get("lon") or request.form.get("manual_lon")
        
        if not lat_str or not lon_str:
            raise ValueError("Missing coordinates")
            
        lat = float(lat_str)
        lon = float(lon_str)
    except ValueError:
        return "Invalid coordinates provided", 400

    is_valid, dist = verify_location(lat, lon)
    
    if not is_valid:
        return render_page(
            "Layer 2 Failed",
            f"""
            <div class="grid">
              <div class="card">
                <h1>❌ Location Check Failed</h1>
                <p class="muted">คุณอยู่นอกพื้นที่ที่กำหนด</p>
                <div class="alert">
                   <strong>Your Location Result:</strong>
                   <p>ห่างจาก มทส. {dist:.2f} กม.</p>
                   <p class="text-error">ต้องไม่เกิน {MAX_DISTANCE_KM} กม.</p>
                </div>
                <a class="btn" href="/stage2">Try Again</a>
              </div>
            </div>
            """,
            subtitle="Location Verification Failed"
        ), 403
    
    if 3 not in progress:
        progress.append(3)
    resp = make_response("", 302)
    resp.headers["Location"] = "/stage2"
    set_progress_cookie(resp, progress)
    return resp

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

    progress = get_progress()
    if 3 not in progress:
        return "Complete all previous layers first (1-3)", 403

    username = request.form.get("username", "").strip()
    otp = request.form.get("otp", "").strip()

    if username not in USERS:
        return "Unknown user.", 400

    seed = "server-room-sut-2026"
    expected = current_otp_code(seed)
    if otp != expected:
        return f"OTP invalid. (Expected: {expected} for debugging)", 403

    # ✅ All layers completed!
    if 4 not in progress:
        progress.append(4)
    
    sid = new_session(username)
    resp = make_response(render_page(
        "Authentication Complete",
        """
        <div class="grid">
          <div class="card">
            <h1>🎉 4-Layer Authentication Success!</h1>
            <p class="muted">คุณผ่านทั้ง 4 layers: PIN → Biometric → Location → OTP</p>
            <hr/>
            <div class="row">
              <a class="btn" href="/stage3/ui">Go Stage 3 (Authorization Lab)</a>
              <a class="btn secondary" href="/stage3">Stage 3 API</a>
              <a class="btn secondary" href="/">Home</a>
            </div>
          </div>
        </div>
        """,
        subtitle="All Layers Completed • Session Established"
    ))
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    set_progress_cookie(resp, progress)
    # Clean gate after login (optional)
    resp.delete_cookie("s2gate")
    return resp
