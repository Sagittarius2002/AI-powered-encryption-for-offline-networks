# aes256gcm_crypto.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _load_key() -> bytes:
    b64 = os.environ.get("AES256_GCM_KEY_B64")
    if b64:
        return base64.b64decode(b64)
    if os.path.exists("aes256.key"):
        with open("aes256.key", "r") as f:
            return base64.b64decode(f.read().strip())
    # Dev fallback: ephemeral key per run (client must match)
    return os.urandom(32)

_KEY = _load_key()

def decrypt_aes256_gcm(token_b64: str, aad: bytes = None) -> str:
    raw = base64.b64decode(token_b64.encode())
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(_KEY)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode()