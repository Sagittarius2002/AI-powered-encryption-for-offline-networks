# keygen_aes256gcm.py
import os, base64
key = os.urandom(32)
print("AES256_GCM_KEY_B64 =", base64.b64encode(key).decode())
with open("aes256.key", "w") as f:
    f.write(base64.b64encode(key).decode() + "\n")