import json
import socket
from reverse_crypto import decrypt_reverse
from chacha_crypto import decrypt_chacha20_poly1305
from aes256gcm_crypto import decrypt_aes256_gcm

HOST = "0.0.0.0"
PORT = 5000
AAD = b"mesh-session-001"  # must match client if used

def handle_envelope(envelope_json: str) -> str:
    """Decrypts the envelope based on the method field."""
    env = json.loads(envelope_json)
    method = env.get("method")
    token = env.get("token", "")

    if method == "Reverse":
        return decrypt_reverse(token)
    elif method == "ChaCha20-Poly1305":
        return decrypt_chacha20_poly1305(token, aad=AAD)
    elif method == "AES-256-GCM":
        return decrypt_aes256_gcm(token, aad=AAD)
    else:
        raise ValueError(f"Unsupported method: {method}")

def recv_all(conn) -> tuple[str, str]:
    """Receives all data from the socket and splits into envelope and prediction."""
    chunks = []
    while True:
        data = conn.recv(4096)
        if not data:
            break
        chunks.append(data)
    full = b"".join(chunks).decode()

    # Split into envelope and prediction if both were sent
    try:
        envelope_json, prediction = full.split("\n", 1)
    except ValueError:
        envelope_json = full
        prediction = "(no prediction received)"
    return envelope_json.strip(), prediction.strip()

if __name__ == "_main_":
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[server] listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[server] connected from {addr}")
                try:
                    envelope_json, prediction = recv_all(conn)

                    print("[server] raw envelope:",
                          envelope_json[:200] + ("..." if len(envelope_json) > 200 else ""))
                    print("[server] raw prediction:", prediction)

                    input_text = handle_envelope(envelope_json)
                    print(f"[server] 🔓 Decrypted input: {input_text}")
                    print(f"[server] 🧠 Prediction result: {prediction}")
                except Exception as e:
                    print("[server] error:", repr(e))