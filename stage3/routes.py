
import json
import time
import hmac
import hashlib
from typing import Tuple, Optional
from flask import request, jsonify, Blueprint
from dataclasses import dataclass

from config import (
    PERMIT_SIGNING_KEY, ACCESS_MATRIX, MLS_LEVEL, ROLES, FLAG
)
from utils import render_page, b64url_encode, b64url_decode, require_session, is_allowed, clearance_at_least

from . import stage3_bp

# =========================================================
# STAGE 3 LOGIC
# =========================================================
@dataclass
class Permit:
    sub: str
    action: str
    resource: str
    attrs: dict
    exp: int

def sign_permit(p: Permit) -> str:
    payload = {
        "sub": p.sub,
        "action": p.action,
        "resource": p.resource,
        "attrs": p.attrs,
        "exp": p.exp,
    }
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(PERMIT_SIGNING_KEY, body.encode("utf-8"), hashlib.sha256).digest()
    return f"{body}.{b64url_encode(sig)}"

def verify_permit(token: str) -> Optional[dict]:
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(PERMIT_SIGNING_KEY, body.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(b64url_decode(sig), expected):
            return None
        payload = json.loads(b64url_decode(body).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def stage3_policy_check(user: dict, action: str, resource: str, attrs: dict) -> Tuple[bool, str]:
    """
    Rule-based + ABAC + MLS
    - target: flag/read
    - require attrs: location=SUT-F1, clearance=SECRET
    - MLS: user clearance >= SECRET
    """
    if resource != "flag" or action != "read":
        return False, "Unknown policy target."

    if attrs.get("location") != "SUT-F1":
        return False, "Policy: location mismatch."

    if attrs.get("clearance") != "SECRET":
        return False, "Policy: clearance attribute mismatch."

    if not clearance_at_least(user.get("clearance", "PUBLIC"), "SECRET"):
        return False, "MLS: user clearance too low."

    return True, "Policy satisfied."

# =========================================================
# ROUTES
# =========================================================

@stage3_bp.get('/stage3')
def index():
    sess, err = require_session()
    if err:
        return err[0], err[1]

    role = sess["role"]
    if not is_allowed(role, "stage3.dashboard"):
        return jsonify({"ok": False, "error": "Access Denied"}), 403

    return jsonify({
        "ok": True,
        "msg": "Stage 3 dashboard",
        "you": sess,
        "endpoints": {
            "policy": "/stage3/policy",
            "request_permit": "POST /stage3/request-permit (JSON)",
            "read_flag": "GET /stage3/flag (optional header: X-Permit)",
        }
    })

@stage3_bp.get('/stage3/ui')
def ui():
    sess, err = require_session()
    if err:
        return render_page(
            "Stage 3 — Unauthorized",
            """
            <div class="grid">
              <div class="card">
                <h1>⛔ Not logged in</h1>
                <p class="muted">คุณต้องผ่าน Stage 2 ก่อน เพื่อได้ session cookie</p>
                <div class="row">
                  <a class="btn" href="/stage2">Go Stage 2</a>
                  <a class="btn secondary" href="/">Home</a>
                </div>
              </div>
            </div>
            """,
            subtitle="Authorization Lab • Session Required"
        ), 401

    role = sess["role"]
    body = f"""
    <div class="grid">
      <div class="card">
        <h1>🧾 Stage 3 — Authorization Lab</h1>
        <p class="muted">RBAC + Access Control Matrix + ABAC/Rule + MLS</p>
        <hr/>
        <div class="row">
          <span class="badge neon">role: {role}</span>
          <span class="badge">dept: {sess.get("dept")}</span>
          <span class="badge pink">clearance: {sess.get("clearance")}</span>
        </div>
      </div>

      <div class="card half">
        <h3>Access Control Matrix</h3>
        <pre id="acm">{json.dumps(ACCESS_MATRIX, indent=2)}</pre>
        <button class="btn secondary" id="acm-btn" onclick="copyText('acm')">Copy</button>
      </div>

      <div class="card half">
        <h3>Policy (ABAC/Rule + MLS)</h3>
        <pre id="pol">{json.dumps({
          "target": {"resource":"flag","action":"read"},
          "require_attrs": {"location":"SUT-F1","clearance":"SECRET"},
          "mls_requirement": "user clearance >= SECRET",
          "permit_ttl_sec": 60
        }, indent=2)}</pre>
        <button class="btn secondary" id="pol-btn" onclick="copyText('pol')">Copy</button>
      </div>

      <div class="card">
        <h3>How to request permit</h3>
        <p class="muted">ส่ง JSON ไปที่ <span class="kbd">POST /stage3/request-permit</span></p>
        <pre id="req">curl -X POST http://localhost:5000/stage3/request-permit \\
  -H "Content-Type: application/json" \\
  -d '{{"action":"read","resource":"flag","attrs":{{"location":"SUT-F1","clearance":"SECRET"}}}}'</pre>
        <div class="row">
          <button class="btn secondary" id="req-btn" onclick="copyText('req')">Copy</button>
          <a class="btn secondary" href="/stage3/policy">Open /stage3/policy (JSON)</a>
          <a class="btn pink" href="/stage3/flag">Try read flag (needs X-Permit)</a>
        </div>
        <p class="muted">ได้ permit แล้วให้ยิง <span class="kbd">GET /stage3/flag</span> พร้อม header <span class="kbd">X-Permit</span></p>
      </div>
    </div>
    """
    return render_page("Stage 3 — Authorization", body, subtitle="Permit-Based Access • Enforced by Policy Engine")

@stage3_bp.get('/stage3/policy')
def policy():
    sess, err = require_session()
    if err:
        return err[0], err[1]

    return jsonify({
        "ok": True,
        "rbac_roles": ROLES,
        "access_control_matrix": ACCESS_MATRIX,
        "rule_based_policy": {
            "target": {"resource": "flag", "action": "read"},
            "require_attrs": {"location": "SUT-F1", "clearance": "SECRET"},
            "mls_requirement": "user clearance >= SECRET",
            "note": "Students need a permit; admins can read directly.",
        }
    })

@stage3_bp.post('/stage3/request-permit')
def request_permit():
    sess, err = require_session()
    if err:
        return err[0], err[1]

    role = sess["role"]
    if not is_allowed(role, "permit.request"):
        return jsonify({"ok": False, "error": "Access Denied"}), 403

    data = request.get_json(silent=True) or {}
    action = data.get("action")
    resource = data.get("resource")
    attrs = data.get("attrs") or {}

    ok, reason = stage3_policy_check(sess, action, resource, attrs)
    if not ok:
        return jsonify({"ok": False, "error": reason}), 403

    p = Permit(
        sub=sess["sub"],
        action=action,
        resource=resource,
        attrs=attrs,
        exp=int(time.time()) + 60,
    )
    token = sign_permit(p)
    return jsonify({"ok": True, "permit": token, "exp_in_sec": 60})

@stage3_bp.get('/stage3/flag')
def get_flag():
    sess, err = require_session()
    if err:
        return err[0], err[1]

    role = sess["role"]

    # Admin ผ่าน RBAC ได้เลย
    if is_allowed(role, "flag.read"):
        return jsonify({"ok": True, "flag": FLAG, "by": "RBAC(admin)"}), 200

    # Student ต้องมี permit
    permit = request.headers.get("X-Permit", "").strip()
    if not permit:
        return jsonify({"ok": False, "error": "Admins only OR provide X-Permit."}), 403

    payload = verify_permit(permit)
    if not payload:
        return jsonify({"ok": False, "error": "Invalid/expired permit."}), 403

    if payload.get("sub") != sess["sub"]:
        return jsonify({"ok": False, "error": "Permit subject mismatch."}), 403
    if payload.get("resource") != "flag" or payload.get("action") != "read":
        return jsonify({"ok": False, "error": "Permit scope mismatch."}), 403

    return jsonify({"ok": True, "flag": FLAG, "by": "Permit(ABAC+MLS)"}), 200
