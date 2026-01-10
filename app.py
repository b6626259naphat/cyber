
from flask import Flask
from stage1 import stage1_bp
from stage2 import stage2_bp
from stage3 import stage3_bp
from utils import render_page

app = Flask(__name__)

# Register Blueprints
app.register_blueprint(stage1_bp)
app.register_blueprint(stage2_bp)
app.register_blueprint(stage3_bp)

@app.get("/")
def home():
    body = """
    <div class="grid">
      <div class="card">
        <h1>🛡️ The SUT Secret Server — CTF Lab</h1>
        <p class="muted">Cyber Security Fundamentals • Blueprint: Crypto → Authentication → Authorization</p>
        <hr/>
        <div class="row">
          <a class="btn" href="/stage1">Start Stage 1</a>
          <a class="btn secondary" href="/stage2">Open Stage 2</a>
          <a class="btn secondary" href="/stage3/ui">Open Stage 3 UI</a>
        </div>
        <p class="muted">Hint: ใช้แนวคิด “จับมือ/ยืนยันตัวตน/กำหนดสิทธิ์” เหมือนระบบจริง (แต่ตั้งใจทำให้เป็นโจทย์ CTF)</p>
      </div>

      <div class="card half">
        <h2>🧩 Stage 1 — Cryptography Chain</h2>
        <p>DH → SHA-256 → AES-GCM → RSA Signature Verify</p>
        <p class="muted">ได้ Password เพื่อ unlock Stage 2</p>
      </div>

      <div class="card half">
        <h2>🔐 Stage 2 — MFA Authentication</h2>
        <p>Unlock Password + OTP (QR)</p>
        <p class="muted">ผ่านแล้วได้ session cookie สำหรับ Stage 3</p>
      </div>

      <div class="card">
        <h2>🧾 Stage 3 — Authorization Lab</h2>
        <p>RBAC + Access Control Matrix + ABAC/Rule + MLS</p>
        <p class="muted">ต้อง “ขอ permit” ให้ถูก policy ก่อนอ่าน Flag</p>
      </div>
    </div>
    """
    return render_page("The SUT Secret Server", body, subtitle="Cyber Lab Interface • Terminal / Neon Theme")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
