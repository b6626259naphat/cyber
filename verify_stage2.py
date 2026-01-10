
import requests
import json
import hmac
import hashlib
import time
import sys
from urllib.parse import unquote

# Configuration
BASE_URL = "http://localhost:5001"
STAGE2_PASSWORD = "SUT_Gate_Open"
USERNAME = "fame"

def step(name):
    print(f"\n[+] Testing: {name}")

def fail(msg, res=None):
    print(f"[-] FAILED: {msg}")
    if res:
        print(f"    Status Code: {res.status_code}")
        print(f"    Response text preview: {res.text[:500]}...")
    sys.exit(1)

def main():
    s = requests.Session()

    # 1. Unlock Stage 2 Gate
    step("Unlock Stage 2 Gate")
    res = s.post(f"{BASE_URL}/stage2/unlock", data={"password": STAGE2_PASSWORD})
    if res.status_code != 200 and len(res.history) == 0: # Expect redirect
         # Note: requests follows redirects by default, so if successful we land on /stage2 (200)
         pass 
    
    # Check if we have the gate cookie
    if "s2gate" not in s.cookies:
        fail("No s2gate cookie found after unlock")
    print("   Gate unlocked successfully.")

    # 2. Check Initial State (Should ask for PIN)
    step("Check Initial State (Layer 1: PIN)")
    res = s.get(f"{BASE_URL}/stage2")
    if "Layer 1: PIN" not in res.text:
         print(f"DEBUG: Status={res.status_code}, Text[:200]={res.text[:200]}")
         fail("Page content missing expected layers", res)
    if "Challenge:" not in res.text:
         fail("PIN Challenge not found")
    
    # Extract question (simple parsing or just brute force answer since we know logic)
    # The logic in routes.py checks against STAGE2_PIN_QUESTIONS.
    # Since we can't easily parse the specific question from HTML without BS4, 
    # we can try to guess or use the fact that I know the answers are 2, 4, 9.
    # But wait, the route code checks: pin.strip() == question["answer"]
    # I can try all valid answers?
    # Or I can cheat and just send the right answer if I can parse the question.
    # For now, let's just try to answer "correctly" by trying to parse.
    
    first_q_res = s.get(f"{BASE_URL}/stage2")
    magic_num_encoded = first_q_res.headers.get("X-SUT-Magic")
    if not magic_num_encoded:
        fail("Could not find X-SUT-Magic header")
    
    magic_num = unquote(magic_num_encoded)
    print(f"   Found Magic Number (Header Encoded): {magic_num_encoded}")
    print(f"   Decoded Magic Number: {magic_num}")
    
    layer1_passed = False
    # Send Magic Number as PIN
    res = s.post(f"{BASE_URL}/stage2/layer2", data={"pin": magic_num})
    if res.status_code == 200: 
        if "Layer 2: Behavioral Biometrics" in res.text or "Keystroke Dynamics" in res.text:
            layer1_passed = True
            print(f"   PIN {magic_num} accepted!")
    
    if not layer1_passed:
        fail("Could not pass Layer 1 PIN challenge")

    # 3. Layer 2: Keystroke Dynamics
    step("Layer 2: Keystroke Simulation")
    # Try invalid phrase
    res = s.post(f"{BASE_URL}/stage2/layer_bio", data={"phrase": "WRONG-PHRASE", "duration": "2000"})
    if "Keystroke Analysis Failed" not in res.text:
        fail("Did not get error for invalid phrase")
    print("   Invalid phrase rejected correctly.")
    
    # Try invalid duration (Too fast)
    res = s.post(f"{BASE_URL}/stage2/layer_bio", data={"phrase": "SUT-CYBER-LAB-2026", "duration": "100"})
    if "Keystroke Analysis Failed" not in res.text:
        fail("Did not get error for too fast typing")
    print("   Too fast typing rejected correctly.")

    # Try valid
    res = s.post(f"{BASE_URL}/stage2/layer_bio", data={"phrase": "SUT-CYBER-LAB-2026", "duration": "2500"})
    if "Layer 3: Location" not in res.text:
         fail("Did not advance to Layer 3 after valid keystroke")
    print("   Valid keystroke accepted.")

    # 4. Layer 3: Location
    step("Layer 3: Location")
    # Valid Coords
    sut_lat, sut_lon = 14.882208, 102.021877
    res = s.post(f"{BASE_URL}/stage2/layer_loc", data={"lat": sut_lat, "lon": sut_lon})
    if "Layer 4: OTP" not in res.text:
         fail("Did not advance to Layer 4 after valid location")
    print("   Location accepted.")

    # 5. Layer 4: OTP
    step("Layer 4: OTP")
    # generating OTP locally
    seed = "server-room-sut-2026"
    t = int(time.time() // 30)
    msg = str(t).encode("utf-8")
    key = seed.encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    num = int.from_bytes(digest[-4:], "big") % 1_000_000
    otp = f"{num:06d}"
    
    print(f"   Generated OTP: {otp}")
    
    res = s.post(f"{BASE_URL}/stage2/login", data={"username": USERNAME, "otp": otp})
    
    if "Authentication Success" not in res.text:
        fail("Login failed")
    
    if "sid" not in s.cookies:
        fail("No session cookie set")
        
    print("   Login success! Session established.")
    print("\n[+] VERIFICATION COMPLETE: ALL CHECKS PASSED")

if __name__ == "__main__":
    main()
