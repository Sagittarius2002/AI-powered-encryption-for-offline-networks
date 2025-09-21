# chacha_crypto.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def _load_key() -> bytes:
    b64 = os.environ.get("CHACHA20P1305_KEY_B64")
    if b64:
        return base64.b64decode(b64)
    if os.path.exists("chacha20.key"):
        with open("chacha20.key", "r") as f:
            return base64.b64decode(f.read().strip())
    # Dev fallback: ephemeral key per run (client must match)
    return os.urandom(32)

_KEY = _load_key()

def decrypt_chacha20_poly1305(token_b64: str, aad: bytes = None) -> str:
    raw = base64.b64decode(token_b64.encode())
    nonce, ct = raw[:12], raw[12:]
    chacha = ChaCha20Poly1305(_KEY)
    pt = chacha.decrypt(nonce, ct, aad)
    return pt.decode()