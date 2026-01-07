
import hashlib
import binascii
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# 1. Params
p = 99991
g = 5
A = 61205
# 1. Params
p = 99991
g = 5
A = 61205
b = 41

# 2. Shared Secret
s = pow(A, b, p)
print(f"s (A^b mod p) = {s}")

# 3. Key
key = hashlib.sha256(str(s).encode("utf-8")).digest()
print(f"Key = {key.hex()}")

# 5. Encrypt (AES-ECB)
payload = {"pass": "SUT_Gate_Open"}
data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
print(f"Plaintext data: {data}")

# Pad
padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()
print(f"Padded data: {padded_data.hex()}")

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(padded_data) + encryptor.finalize()
ct_hex = ct.hex()
print(f"Calculated Ciphertext: {ct_hex}")

# Compare with Blueprint Ciphertext
blueprint_ct = "964724a20f9269557454238719c23730e2380590457697422944b25187768407"
if ct_hex == blueprint_ct:
    print("SUCCESS: Matches Blueprint Ciphertext exactly!")
else:
    print(f"WARNING: Differs from Blueprint.\nExpected: {blueprint_ct}\nGot:      {ct_hex}")

# 6. Decrypt Verify
decryptor = cipher.decryptor()
pt_padded = decryptor.update(ct) + decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
pt = unpadder.update(pt_padded) + unpadder.finalize()
print(f"Decrypted: {pt.decode('utf-8')}")
