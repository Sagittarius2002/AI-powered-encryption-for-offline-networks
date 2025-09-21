import socket
import json
import joblib
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

# ===== Reverse (low security) =====
def encrypt_reverse(plaintext: str) -> str:
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    return plaintext[::-1]

# ===== ChaCha20-Poly1305 (medium) =====
def load_chacha_key() -> bytes:
    b64 = os.environ.get("CHACHA20P1305_KEY_B64")
    if b64:
        return base64.b64decode(b64)
    if os.path.exists("chacha20.key"):
        with open("chacha20.key", "r") as f:
            return base64.b64decode(f.read().strip())
    raise RuntimeError("ChaCha20 key not found. Generate with keygen_chacha20.py")

def encrypt_chacha20_poly1305(plaintext: str, aad: bytes = None) -> str:
    key = load_chacha_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, plaintext.encode(), aad)
    return base64.b64encode(nonce + ct).decode()

# ===== AES-256-GCM (strongest) =====
def load_aes256_key() -> bytes:
    b64 = os.environ.get("AES256_GCM_KEY_B64")
    if b64:
        return base64.b64decode(b64)
    if os.path.exists("aes256.key"):
        with open("aes256.key", "r") as f:
            return base64.b64decode(f.read().strip())
    raise RuntimeError("AES-256-GCM key not found. Generate with keygen_aes256gcm.py")

def encrypt_aes256_gcm(plaintext: str, aad: bytes = None) -> str:
    key = load_aes256_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), aad)
    return base64.b64encode(nonce + ct).decode()

# ===== ML prediction =====
def predict_column(input_text: str, models_dict: dict) -> str:
    input_text = input_text.strip().lower()
    scores = {}
    for col, (clf, vectorizer) in models_dict.items():
        try:
            X_vec = vectorizer.transform([input_text])
            prob = clf.predict_proba(X_vec)[0]
            max_conf = max(prob)
            scores[col] = max_conf
        except Exception:
            scores[col] = 0.0
    predicted_col = max(scores, key=scores.get)
    confidence = round(scores[predicted_col], 2)
    return f"Column: {predicted_col}, Confidence: {confidence}"

# ===== Networking (send envelope + result) =====
def send_to_server(ip: str, port: int, envelope_json: str, result_text: str):
    # One TCP connection; envelope on line 1, prediction on line 2
    payload = envelope_json + "\n" + result_text
    s = socket.socket()
    s.connect((ip, port))
    s.sendall(payload.encode())
    # try:
    #     s.connect((ip, port))
    #     s.sendall(payload.encode())
    # finally:
    #     s.close()


from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import torch

# Load the saved model and tokenizer
tokenizer = DistilBertTokenizerFast.from_pretrained("./distilbert_risk_model")
model = DistilBertForSequenceClassification.from_pretrained("./distilbert_risk_model")

# Map numeric labels back to human-readable classes
label_map = {0: "High Risk", 1: "Moderate Risk", 2: "Low Risk"}

def classify_text(text):
    # Tokenize the input
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=64)
    
    # Run inference without gradient calculation
    with torch.no_grad():
        outputs = model(**inputs)
        predicted_class_id = torch.argmax(outputs.logits, dim=1).item()
    
    return label_map[predicted_class_id]


import time


# ===== Main =====
if __name__ == "__main__":
    # Load ML models dict: { column_name: (clf, vectorizer), ... }
    # models = joblib.load("sensitive_column_models.joblib")

    # Save model and tokenizer
    model.save_pretrained("./distilbert_risk_model")
    tokenizer.save_pretrained("./distilbert_risk_model")

    # User input and prediction
    input_value = input("Enter text message: ")
    result = classify_text(input_value)
    print("🔮 Final prediction:", result)

    # Choose encryption method at runtime
    # print("\nChoose encryption method:")
    # print("1. Reverse (low security)")
    # print("2. ChaCha20-Poly1305 (medium security)")
    # print("3. AES-256-GCM (strongest)")
    # choice = input("Enter choice [1/2/3]: ").strip()

    AAD = b"mesh-session-001"  # must match server if used

    # if choice == "1":
    #     method = "Reverse"
    #     token = encrypt_reverse(input_value)
    # elif choice == "2":
    #     method = "ChaCha20-Poly1305"
    #     token = encrypt_chacha20_poly1305(input_value, aad=AAD)
    # elif choice == "3":
    #     method = "AES-256-GCM"
    #     token = encrypt_aes256_gcm(input_value, aad=AAD)
    # else:
    #     raise ValueError("Invalid choice")
    
    if result == "Low Risk":
        method = "Reverse"
        token = encrypt_reverse(input_value)
    elif result == "Moderate Risk":
        method = "ChaCha20-Poly1305"
        token = encrypt_chacha20_poly1305(input_value, aad=AAD)
    elif result == "High Risk":
        method = "AES-256-GCM"
        token = encrypt_aes256_gcm(input_value, aad=AAD)
    else:
        raise ValueError("Invalid choice")

    # Wrap encrypted input in the envelope the server expects
    envelope = json.dumps({"method": method, "token": token})

    # Send both: encrypted input (envelope) + plaintext prediction
    SERVER_IP = "10.178.106.151"  # replace with your server IP
    PORT = 5000
    # Before sending
    start_time = time.time()
    send_to_server(SERVER_IP, PORT, envelope, result)

    # After sending
    end_time = time.time()
    elapsed_ms = round((end_time - start_time) * 1000, 2)
    print(f"⏱️ Message sent in {elapsed_ms} ms")
    print(f"📤 Sent using {method}: input (encrypted) + prediction (plaintext)")