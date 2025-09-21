# keygen_chacha20.py
import os, base64
key = os.urandom(32)
print("CHACHA20P1305_KEY_B64 =", base64.b64encode(key).decode())
with open("chacha20.key", "w") as f:
    f.write(base64.b64encode(key).decode() + "\n")