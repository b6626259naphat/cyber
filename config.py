
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
        "question": "สีประจำมหาวิทยาลัยเทคโนโลยีสุรนารี มีกี่สี",
        "answer": "2",
        "hint": "ม่วงและส้ม เป็นสีประจำมหาวิทยาลัย"
    },
    {
        "question": "จำนวนสำนักวิชา (Institute) ทั้งหมดใน มทส.",
        "answer": "9",
        "hint": "มี 9 สำนักวิชา: วิทยาศาสตร์, เทคโนโลยีสังคม, เทคโนโลยีการเกษตร, วิศวกรรมศาสตร์, แพทย์, พยาบาล, ทันตแพทย์, สาธารณสุข, ศาสตร์และศิลป์ดิจิทัล"
    },
    {
        "question": "จำนวนปีการศึกษาของหลักสูตร CPE (ปกติ)",
        "answer": "4",
        "hint": "ปริญญาตรี 4 ปี"
    },
    {
        "question": "จำนวนอาคารเรียน F (Faculty Building) ทั้งหมดใน มทส.",
        "answer": "12",
        "hint": "มีอาคาร F1 ถึง F12"
    }
]


# Biometric Simulation: Pattern matching
BIOMETRIC_PATTERN = "CPE:SUT:2023"  # ต้องสร้าง hash จาก pattern นี้

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
