
import secrets

# =========================================================
# CTF CONFIG
# =========================================================
FLAG = "SUT{CPE_CTF_2026_SUCCESS}"

# ✅ Stage 2 password (ได้จาก Stage 1)
STAGE2_PASSWORD_PLAINTEXT = "SUT_Gate_Open"

# ✅ Stage 2 Gate: ต้องถอด Stage1 แล้วเอา pass มา unlock ก่อนถึงเห็น Stage2
STAGE2_GATE_TTL_SECONDS = 10 * 60
STAGE2_GATE_KEY = secrets.token_bytes(32)

# Stage 2 OTP
OTP_WINDOW_SECONDS = 30

# =========================================================
# STAGE 2 MULTI-LAYER MFA CONFIG
# =========================================================
# PIN Challenge: คำถามสุ่มเกี่ยวกับ SUT และ Cyber Security (ตอบเป็นตัวเลข)
STAGE2_PIN_QUESTIONS = [
    {
        "question": "จงหาค่า 'Magic Number'",
        "answer": "234041",
        "hint": "คำใบ้: เลขรหัสวิชา Cyber Security"
    }
]
STAGE2_MAGIC_NUMBER = "234041"


# Biometric Simulation: Pattern matching
# Location-based Verification
SUT_COORDINATES = (14.882208, 102.021877)  # พิกัด มทส. (โดยประมาณ)
MAX_DISTANCE_KM = 5.0  # รัศมีที่ยอมรับ (กิโลเมตร)

# Biometric Configuration (Keystroke Dynamics)
STAGE2_KEYSTROKE_TARGET_PHRASE = "SUT-CYBER-LAB-2026"
STAGE2_KEYSTROKE_MIN_TIME_MS = 500   # Too fast = bot
STAGE2_KEYSTROKE_MAX_TIME_MS = 10000 # Too slow = copy-paste/afk

# Progress tracking key
STAGE2_PROGRESS_KEY = secrets.token_bytes(32)

# Stage 3: MLS levels
MLS_LEVEL = {"PUBLIC": 0, "CONFIDENTIAL": 1, "SECRET": 2}

# RBAC roles
ROLES = ["guest", "student", "admin"]

# Access Control Matrix (ตัวอย่าง)
ACCESS_MATRIX = {
    "guest": {
        "stage3.dashboard": False,
        "flag.read": False,
        "permit.request": False,
    },
    "student": {
        "stage3.dashboard": True,
        "flag.read": False,          # ต้องมี permit เพิ่ม
        "permit.request": True,
    },
    "admin": {
        "stage3.dashboard": True,
        "flag.read": True,           # admin อ่านได้ตรง ๆ
        "permit.request": True,
    },
}

# คีย์เซ็น permit (Stage 3)
PERMIT_SIGNING_KEY = secrets.token_bytes(32)

# จำลอง user DB
# NOTE: ตั้ง fame เป็น SECRET เพื่อให้ Stage 3 ขอ permit แล้วไปอ่าน flag ได้ (flow ไม่ตัน)
USERS = {
    "fame": {"password": None, "role": "student", "dept": "CPE", "clearance": "SECRET"},
    "admin": {"password": None, "role": "admin", "dept": "ITSEC", "clearance": "SECRET"},
}

# session store (in-memory)
SESSIONS = {}
