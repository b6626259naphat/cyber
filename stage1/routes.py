
import json
import secrets
import hashlib
from typing import Tuple
from flask import jsonify, Blueprint, request, render_template_string, make_response
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding, hashes, serialization

from config import STAGE2_PASSWORD_PLAINTEXT
from utils import render_page, b64url_encode

from . import stage1_bp

# =========================================================
# STAGE 1 LOGIC
# =========================================================


# 1. Public Parameters (Hardcoded as per Blueprint)
DH_P = 99991
DH_G = 5
DH_A_PUB = 61205

# Hidden Secret (User must guess/derive this)
# Hint: "Last 2 digits of Cyber subject code" -> 41
DH_B_SECRET = 41

# RSA Key (For consistent signature if needed, though blueprint focuses on AES)
# We keep it for the "Puzzle" completeness if the user wants to verify signature later.
RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUBLIC_PEM = RSA_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

def stage1_compute_shared_secret() -> int:
    # Formula: s = A^b mod p
    # Calculation: 61205^41 mod 99991
    return pow(DH_A_PUB, DH_B_SECRET, DH_P)

def stage1_derive_key_from_s(s: int) -> bytes:
    # Normal derivation (No Glitch)
    return hashlib.sha256(str(s).encode("utf-8")).digest()

def stage1_encrypt_handshake_ecb(key32: bytes) -> str:
    # Ciphertext (The Locked Box)
    # Result: {"pass": "SUT_Gate_Open"}
    
    payload = {"pass": STAGE2_PASSWORD_PLAINTEXT}
    
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key32), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    
    return ct.hex()

# =========================================================
# ROUTES
# =========================================================

@stage1_bp.route('/stage1')
def index():
    s = stage1_compute_shared_secret()
    key32 = stage1_derive_key_from_s(s) 
    
    # User Request: Text Message with Color Codes
    ct_hex = """รบกวนทีมกราฟิกเช็กชุดสีพวกนี้ให้หน่อยครับ ว่าเอาไปใช้กับธีมใหม่ได้ไหม:

Primary: #f152bf

Secondary: #d4585b

Accent 1: #ae1f56

Accent 2: #41e9f4

Background: #819c3d

Text: #17aa49

Error: #f3414f

Warning: #f6f22d

Info: #0f1c65

Link: #277e0b

Icon: #d7a6 """
    # ct_hex = stage1_encrypt_handshake_ecb(key32)

    body = f"""
    <div class="grid">
      <div class="card">
        <h1>🔐 Stage 1 — หากุญแจมาไขกล่อง</h1>
        <hr/>
        
        <h2>หา Shared Secret จาก DH</h2>
        <pre id="params">
Prime Modulus (p): {DH_P}
Generator (g): {DH_G}
Server Public Key (A): {DH_A_PUB}</pre>
  
        
        <p class="mt-2">
            <strong>Hint for Private Key (b):</strong>
            <span class="kbd">s = A^b mod p</span><br/>
            "เลขท้าย 2 ตัวของรหัสวิชา Cyber"
        </p>
      </div>

      <div class="card half">
        <h2>เอาคำตอบจากข้อข้างบน มาใช้กับคำใบ้ข้อนี้ </h2>
        <ol>
            <li><strong>:</strong> <span class="kbd">🍵 - 2<sup>🥚</sup></span> <span class="muted text-small"></span></li>
           
        </ol>
      </div>

      <div class="card half">
        <textarea rows="15" readonly id="ct" style="width:100%; font-family:monospace; color:#0f0; background:#000; border:1px solid #333; padding:10px;">{ct_hex}</textarea>
        <button class="btn" onclick="copyText('ct')">Copy </button>
        
        <p class="mt-2 text-small muted">
          
        </p>
      </div>

      <div class="card">
        <h3>🚪 Unlock Stage 2</h3>
        <form method="post" action="/stage2/unlock">
          <div class="row">
            <input name="password" placeholder="ใส่รหัสที่ถอดได้ " style="flex-grow:1;" />
            <button class="btn primary" type="submit">Unlock</button>
          </div>
        </form>
      </div>

      <script>
        // Simulate Security Info in F12 Console
        console.group("%c🔒 Security Connection (Simulated)", "color: #2ea44f; font-size: 14px; font-weight: bold;");
        //console.log("%cProtocol:       %cTLS 1.3", "color: #8b949e;", "color: #58a6ff; font-weight: bold;");
        //console.log("%cKey Exchange:   %cX25519", "color: #8b949e;", "color: #58a6ff; font-weight: bold;");
        console.log("%cEncryption:     %cAES-256-ECB", "color: #8b949e;", "color: #58a6ff; font-weight: bold;");
        console.log("%cKey Derivation: %cSHA-256(str(s))", "color: #8b949e;", "color: #58a6ff; font-weight: bold;");
        console.groupEnd();
      </script>
    </div>
    """
    resp_str = render_page(
        title="Stage 1 — Secure Handshake",
        body_html=body
    )
    resp = make_response(resp_str)
    
    # Add Simulated Headers (Visible in F12 Network Tab)
    resp.headers["X-Simulated-Protocol"] = "TLS 1.3"
    resp.headers["X-Simulated-Cipher"] = "AES-256-ECB"
    
    return resp

@stage1_bp.route('/stage1/handshake.json')
def handshake_json():
    s = stage1_compute_shared_secret()
    key32 = stage1_derive_key_from_s(s)
    
    # User Request: Text Message with Color Codes
    ct_hex = """รบกวนทีมกราฟิกเช็กชุดสีพวกนี้ให้หน่อยครับ ว่าเอาไปใช้กับธีมใหม่ได้ไหม:

Primary: #f152bf

Secondary: #d4585b

Accent 1: #ae1f56

Accent 2: #41e9f4

Background: #819c3d

Text: #17aa49

Error: #f3414f

Warning: #f6f22d

Info: #0f1c65

Link: #277e0b

Icon: #d7a600 (เติม 00 ให้ครบ)"""
    # ct_hex = stage1_encrypt_handshake_ecb(key32)
    
    return jsonify({
        "public_parameters": {
            "p": DH_P,
            "g": DH_G,
            "A": DH_A_PUB
        },
        "hint": "Last 2 digits of Cyber subject code (b=41)",
        "ciphertext_hex": ct_hex,
        "encryption_mode": "AES-256-ECB",
        "key_derivation": "SHA-256(str(s))"
    })
