
import json
import secrets
import hashlib
from typing import Tuple
from flask import jsonify, Blueprint
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

from config import STAGE2_PASSWORD_PLAINTEXT
from utils import render_page, b64url_encode

from . import stage1_bp

# =========================================================
# STAGE 1 LOGIC
# =========================================================

# DH parameters (คำนวณเร็ว เหมาะ CTF demo)
DH_P = 2147483647  # 2^31 - 1 (prime)
DH_G = 5

# Hint: b = เลขท้าย 2 ตัวของปี พ.ศ. ที่ก่อตั้ง มทส. (ตัวอย่าง 33)
DH_B_SECRET = 33

# Server DH private/public
DH_A_PRIV = secrets.randbelow(DH_P - 2) + 2
DH_A_PUB = pow(DH_G, DH_A_PRIV, DH_P)  # A = g^a mod p

# RSA keypair สำหรับ signature
RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUBLIC_PEM = RSA_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

def stage1_compute_shared_secret() -> int:
    return pow(DH_A_PUB, DH_B_SECRET, DH_P)

def stage1_derive_key_from_s(s: int) -> bytes:
    return hashlib.sha256(str(s).encode("utf-8")).digest()

def stage1_make_signature(message: str) -> bytes:
    return RSA_PRIVATE_KEY.sign(
        message.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

def stage1_encrypt_handshake_json(key32: bytes) -> Tuple[str, str]:
    aesgcm = AESGCM(key32)
    nonce = secrets.token_bytes(12)

    password = STAGE2_PASSWORD_PLAINTEXT
    sig = stage1_make_signature(password)

    payload = {
        "pass": password,
        "sign": b64url_encode(sig),
    }
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return b64url_encode(nonce), b64url_encode(ct)

# =========================================================
# ROUTES
# =========================================================

@stage1_bp.route('/stage1')
def index():
    s = stage1_compute_shared_secret()
    key32 = stage1_derive_key_from_s(s)
    nonce_b64, ct_b64 = stage1_encrypt_handshake_json(key32)

    body = f"""
    <div class="grid">
      <div class="card">
        <h1>🔐 Stage 1 — Secure Handshake</h1>
        <p class="muted">DH ➜ Hash ➜ AES Decrypt ➜ RSA Signature Verify (ครบ 5 เทคนิค)</p>
        <hr/>
        <h2>Mission</h2>
        <p>ถอดรหัสเพื่อหา <span class="kbd">Password</span> สำหรับ Stage 2 และยืนยันความถูกต้องด้วย <span class="kbd">Digital Signature</span></p>
      </div>

      <div class="card half">
        <h3>1) Diffie-Hellman</h3>
        <p class="muted">Public parameters + Server Public Key</p>
        <pre id="dh">
p = {DH_P}
g = {DH_G}
A = {DH_A_PUB}</pre>
        <div class="row">
          <button class="btn secondary" id="dh-btn" onclick="copyText('dh')">Copy</button>
          <span class="muted">Hint: b = เลขท้าย 2 ตัวของปี พ.ศ. ที่ก่อตั้ง มทส. (เช่น 33)</span>
        </div>
        <p>คำนวณ <span class="kbd">s = A^b mod p</span></p>
      </div>

      <div class="card half">
        <h3>2) Hash ➜ Key</h3>
        <p>ทำ <span class="kbd">SHA-256(str(s))</span> ได้ key 32 bytes แล้วไปถอด AES</p>
        <details>
          <summary>ดูแนวทาง (Hint)</summary>
          <p class="muted">ใน Python: <span class="kbd">hashlib.sha256(str(s).encode()).digest()</span></p>
        </details>
      </div>

      <div class="card">
        <h3>3) Symmetric — AES-GCM</h3>
        <p class="muted">Use derived key to decrypt ciphertext</p>
        <pre id="aes">nonce (b64url) = {nonce_b64}
ciphertext (b64url) = {ct_b64}</pre>
        <div class="row">
          <button class="btn secondary" id="aes-btn" onclick="copyText('aes')">Copy</button>
          <a class="btn" href="/stage1/handshake.json">Open handshake.json</a>
          <a class="btn secondary" href="/stage2">Go Stage 2 (Locked until Unlock)</a>
        </div>
        <p>ผลลัพธ์ที่ได้หลังถอดรหัส: JSON <span class="kbd">{{"pass":"...","sign":"..."}}</span></p>
      </div>

      <div class="card">
        <h3>4) Asymmetric + Digital Signature</h3>
        <p class="muted">Verify signature of <span class="kbd">pass</span> using RSA public key</p>
        <details>
          <summary>แสดง RSA Public Key (PEM)</summary>
          <pre id="rsa">{RSA_PUBLIC_PEM}</pre>
          <div class="row">
            <button class="btn secondary" id="rsa-btn" onclick="copyText('rsa')">Copy</button>
          </div>
        </details>
        <p>ถ้า verify ผ่าน แปลว่า password “ของจริง” ✅</p>
      </div>

      <div class="card">
        <h3>🚪 Unlock Stage 2</h3>
        <p class="muted">ถ้าถอดรหัสได้แล้ว ให้นำ <span class="kbd">pass</span> มาใส่ตรงนี้เพื่อเปิดด่าน 2</p>
        <form method="post" action="/stage2/unlock">
          <label>Password (from decrypted JSON)</label>
          <input name="password" placeholder="paste pass here (e.g., SUT_Gate_Open)" />
          <button class="btn" type="submit">Unlock & Go Stage 2</button>
        </form>
        <small class="muted">ผ่านแล้วจะได้ cookie <span class="kbd">s2gate</span> (หมดอายุภายใน ~10 นาที)</small>
      </div>
    </div>
    """
    return render_page(
        title="Stage 1 — Secure Handshake",
        subtitle="CRYPTO CHAIN: DH → SHA-256 → AES-GCM → RSA Signature",
        body_html=body
    )

@stage1_bp.route('/stage1/handshake.json')
def handshake_json():
    s = stage1_compute_shared_secret()
    key32 = stage1_derive_key_from_s(s)
    nonce_b64, ct_b64 = stage1_encrypt_handshake_json(key32)
    return jsonify({
        "dh": {"p": DH_P, "g": DH_G, "A": DH_A_PUB, "b_hint": "last 2 digits of SUT founded year (example 33)"},
        "hash": {"key": "SHA-256(str(s))"},
        "aes": {"mode": "AES-GCM", "nonce_b64url": nonce_b64, "ciphertext_b64url": ct_b64},
        "rsa_public_key_pem": RSA_PUBLIC_PEM,
        "goal": "Decrypt AES -> get JSON(pass, sign). Verify RSA signature for pass.",
    })
