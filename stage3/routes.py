# stage3/routes.py

import json
import time
import hmac
import hashlib
import base64
from typing import Tuple, Optional
from flask import request, jsonify, Blueprint
from dataclasses import dataclass

from config import (
    PERMIT_SIGNING_KEY, ACCESS_MATRIX, MLS_LEVEL, ROLES, FLAG
)
from utils import render_page, b64url_encode, b64url_decode, require_session, is_allowed, clearance_at_least

from . import stage3_bp

# =========================================================
# STAGE 3 LOGIC: CIRCUIT DECODER
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

def check_circuit_status(attrs: dict) -> dict:
    """
    ตรวจสอบรหัสปลดล็อกวงจรทีละชั้น (Circuit Breakers)
    ผู้เล่นต้องส่งค่าที่ Decode แล้วมาให้ถูกต้อง
    """
    status = {
        "b1": False, # Breaker 1: RBAC Override
        "b2": False, # Breaker 2: MLS Override
        "b3": False, # Breaker 3: Master PIN
        "all_pass": False,
        "logs": []
    }
    
    # --- BREAKER 1: RBAC OVERRIDE ---
    # Hint: TUFJTlRfT1ZFUlJJREU=  => Decode ได้ "MAINT_OVERRIDE"
    # Octal: 115 101 111 116 124 137 117 126 105 122 122 111 104 105
    code1 = attrs.get("code_1", "").strip()
    if code1 == "MAINT_OVERRIDE":
        status["b1"] = True
        status["logs"].append("✅ Breaker 1 (RBAC): Bypassed via Maintenance Code.")
    else:
        status["logs"].append("❌ Breaker 1 (RBAC): Locked. Invalid Override Code.")

    # --- BREAKER 2: MLS OVERRIDE ---
    # Hint: UEhZU0lDQUxfQUNDRVNT => Decode ได้ "PHYSICAL_ACCESS"
    # Octal: 120 110 131 123 111 103 101 114 137 101 103 103 105 123 123
    code2 = attrs.get("code_2", "").strip()
    if code2 == "PHYSICAL_ACCESS":
        status["b2"] = True
        status["logs"].append("✅ Breaker 2 (MLS): Bypassed via Physical Access Code.")
    else:
        status["logs"].append("❌ Breaker 2 (MLS): Locked. Invalid Access Code.")

    # --- BREAKER 3: MASTER SWITCH ---
    # Hint: Nzc4OA== => Decode ได้ "7788"
    # Octal: 067 067 070 070
    code3 = attrs.get("code_3", "").strip()
    if code3 == "7788":
        status["b3"] = True
        status["logs"].append("✅ Breaker 3 (Master): PIN Verified.")
    else:
        status["logs"].append("❌ Breaker 3 (Master): Locked. Invalid PIN.")

    # FINAL CHECK
    if status["b1"] and status["b2"] and status["b3"]:
        status["all_pass"] = True
        status["logs"].append("🎉 SYSTEM UNLOCKED: Emergency Permit Generated.")
    
    return status

# =========================================================
# ROUTES
# =========================================================

@stage3_bp.get('/stage3')
def index():
    sess, err = require_session()
    if err: return err[0], err[1]
    
    return jsonify({
        "ok": True,
        "msg": "Circuit Decoder Dashboard",
        "endpoints": {
            "ui": "/stage3/ui",
            "test_circuit": "POST /stage3/request-permit"
        }
    })

@stage3_bp.get('/stage3/ui')
def ui():
    sess, err = require_session()
    if err:
        return render_page("Stage 3", "<h1>Not logged in</h1>", "Error"), 401

    role = sess["role"]
    
    script_content = """
    <script>
    function testCircuit() {
        var c1 = document.getElementById('inp-c1').value;
        var c2 = document.getElementById('inp-c2').value;
        var c3 = document.getElementById('inp-c3').value;
        var btn = document.getElementById('btn-test');
        
        btn.innerText = 'Testing Circuits...';
        btn.disabled = true;

        fetch('/stage3/request-permit', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                action: 'read',
                resource: 'flag',
                attrs: { 
                    code_1: c1, 
                    code_2: c2,
                    code_3: c3
                }
            })
        })
        .then(r => r.json())
        .then(d => {
            btn.disabled = false;
            btn.innerText = '⚡ TEST CONNECTION';
            
            // Update Lights
            setLight('l1', d.status.b1);
            setLight('l2', d.status.b2);
            setLight('l3', d.status.b3);
            
            // Show Logs
            var logHtml = d.logs.map(l => {
                return `<div style="color:${l.includes('✅')?'#2ecc71':'#e74c3c'}">${l}</div>`;
            }).join('');
            document.getElementById('log-box').innerHTML = logHtml;

            if(d.ok) {
                document.getElementById('permit-result').value = d.permit;
                document.getElementById('final-box').style.display = 'block';
                document.getElementById('final-box').scrollIntoView({behavior:'smooth'});
            }
        });
    }

    function setLight(id, on) {
        var el = document.getElementById(id);
        if(on) {
            el.style.backgroundColor = '#2ecc71';
            el.style.boxShadow = '0 0 15px #2ecc71';
            el.innerText = 'ON';
        } else {
            el.style.backgroundColor = '#c0392b';
            el.style.boxShadow = 'none';
            el.innerText = 'OFF';
        }
    }

    function getFlag() {
        var token = document.getElementById('permit-result').value;
        fetch('/stage3/flag', { headers: {'X-Permit': token} })
        .then(r => r.json())
        .then(d => {
            if(d.ok) {
                document.getElementById('flag-result').innerHTML = 
                '<div class="card" style="background:#2ecc71; color:white; margin-top:15px; text-align:center;"><h1>🚩 '+d.flag+'</h1></div>';
            } else {
                alert(d.error);
            }
        });
    }
    </script>
    <style>
        .light { 
            width:60px; height:60px; border-radius:50%; 
            background:#c0392b; border:3px solid #333; margin:0 auto;
            display:flex; align-items:center; justify-content:center;
            font-weight:bold; color:#000; font-size:12px; transition:0.3s;
        }
        .breaker-box {
            background:#111; border:1px solid #333; padding:15px; border-radius:8px;
            text-align:center; position:relative; overflow:hidden;
        }
        .wire {
            position:absolute; top:50%; width:20px; height:4px; background:#444;
        }
        .code-display {
            font-family:monospace; background:#000; color:#00ffd5; padding:4px 8px; border-radius:4px;
            display:inline-block; border:1px solid #00ffd533; font-size:1.1em; letter-spacing:1px;
        }
    </style>
    """

    body = f"""
    {script_content}
    <div class="grid">
      <div class="card">
        <h1>⚡ Stage 3: Security Circuit Decoder</h1>
        <div class="row">
          <span class="badge neon">Role: {role}</span>
          <span class="badge pink">Clearance: {sess.get("clearance")}</span>
        </div>
        <p class="muted">
           <b>Objective:</b> The security system has 3 layers. You must <b>DECODE</b> the bypass signal for each layer
           (either from Base64 or Octal) to turn the lights GREEN and unlock the Master Switch.
        </p>
      </div>

      <div class="card">
        <h3>🔌 System Status Panel</h3>
        <div class="grid" style="grid-template-columns: 1fr 1fr 1fr; gap:10px;">
            <div class="breaker-box">
                <div id="l1" class="light">OFF</div>
                <div style="margin-top:10px; color:#aaa;">Breaker 1</div>
                <div style="font-size:0.8em; color:#666;">RBAC</div>
            </div>
            <div class="breaker-box">
                <div id="l2" class="light">OFF</div>
                <div style="margin-top:10px; color:#aaa;">Breaker 2</div>
                <div style="font-size:0.8em; color:#666;">MLS</div>
            </div>
            <div class="breaker-box">
                <div id="l3" class="light">OFF</div>
                <div style="margin-top:10px; color:#aaa;">Breaker 3</div>
                <div style="font-size:0.8em; color:#666;">MASTER</div>
            </div>
        </div>
      </div>

      <div class="card half">
        <h3>1. RBAC Override Signal</h3>
        <p class="muted">Decode this Base64 string to bypass Role check:</p>
        <div style="text-align:center; margin:10px;">
            <span class="code-display">TUFJTlRfT1ZFUlJJREU=</span>
        </div>
        <p class="muted" style="font-size:0.9em; margin-top:5px;">
            OR Decode this <b>Octal (Base8)</b> sequence:<br>
            <span class="code-display" style="font-size:0.85em; color:#f1c40f;">115 101 111 116 124 137 117 126 105 122 122 111 104 105</span>
        </p>
        <input type="text" id="inp-c1" placeholder="Enter Decoded Text..." style="text-align:center;">
        
        <hr>
        
        <h3>2. MLS Override Signal</h3>
        <p class="muted">Decode this Base64 string to bypass Clearance check:</p>
        <div style="text-align:center; margin:10px;">
            <span class="code-display">UEhZU0lDQUxfQUNDRVNT</span>
        </div>
        <p class="muted" style="font-size:0.9em; margin-top:5px;">
            OR Decode this <b>Octal (Base8)</b> sequence:<br>
            <span class="code-display" style="font-size:0.85em; color:#f1c40f;">120 110 131 123 111 103 101 114 137 101 103 103 105 123 123</span>
        </p>
        <input type="text" id="inp-c2" placeholder="Enter Decoded Text..." style="text-align:center;">
      </div>

      <div class="card half">
        <h3>3. Master PIN</h3>
        <p class="muted">Decode this Base64 PIN to unlock the flag vault:</p>
        <div style="text-align:center; margin:10px;">
            <span class="code-display">Nzc4OA==</span>
        </div>
        <p class="muted" style="font-size:0.9em; margin-top:5px;">
            OR Decode this <b>Octal (Base8)</b> sequence:<br>
            <span class="code-display" style="font-size:0.85em; color:#f1c40f;">067 067 070 070</span>
        </p>
        <input type="text" id="inp-c3" placeholder="Enter Decoded PIN..." style="text-align:center; letter-spacing:5px; font-size:1.2em;">
        
        <div style="margin-top:20px;">
            <button class="btn" id="btn-test" onclick="testCircuit()" style="width:100%; height:50px; font-size:1.1em;">
                ⚡ TEST CONNECTION
            </button>
        </div>
        
        <div id="log-box" style="margin-top:15px; background:#000; padding:10px; font-family:monospace; font-size:0.9em; border-radius:5px; min-height:80px;">
            <div style="color:#555">System Ready... Waiting for input.</div>
        </div>
      </div>

      <div class="card" id="final-box" style="display:none; border: 2px solid #2ecc71;">
        <h3 style="color:#2ecc71;">🔓 Access Granted</h3>
        <p>All circuits bypassed. Emergency Token generated.</p>
        <input type="text" id="permit-result" readonly style="width:100%; background:#222; color:#fff; padding:5px; margin-bottom:10px;">
        <button class="btn pink" onclick="getFlag()" style="width:100%;">🚩 Retrieve Flag</button>
        <div id="flag-result"></div>
      </div>

    </div>
    """
    return render_page("Stage 3 - Circuit Decoder", body, "Authorization & Encoding Puzzle")

@stage3_bp.post('/stage3/request-permit')
def request_permit():
    sess, err = require_session()
    if err: return err[0], err[1]

    data = request.get_json(silent=True) or {}
    attrs = data.get("attrs") or {}

    # ตรวจสอบ Logic ทั้ง 3 ชั้น
    status = check_circuit_status(attrs)
    
    if status["all_pass"]:
        # ถ้าผ่านหมด ให้ Permit
        p = Permit(
            sub=sess["sub"],
            action="read",
            resource="flag",
            attrs=attrs,
            exp=int(time.time()) + 60,
        )
        token = sign_permit(p)
        return jsonify({
            "ok": True, 
            "permit": token, 
            "status": status, 
            "logs": status["logs"]
        })
    else:
        # ถ้าไม่ผ่าน ให้ส่ง Status กลับไปเปลี่ยนสีไฟ (แต่ไม่ให้ Permit)
        return jsonify({
            "ok": False, 
            "error": "Circuit Locked", 
            "status": status, 
            "logs": status["logs"]
        }), 403

@stage3_bp.get('/stage3/flag')
def get_flag():
    sess, err = require_session()
    if err: return err[0], err[1]
    
    permit = request.headers.get("X-Permit", "").strip()
    if not permit: return jsonify({"ok": False, "error": "Missing Token"}), 403
    
    payload = verify_permit(permit)
    if not payload: return jsonify({"ok": False, "error": "Invalid Token"}), 403

    return jsonify({"ok": True, "flag": FLAG, "by": "Circuit Decoder (ABAC+Rule)"}), 200