import random
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from cryptography.fernet import Fernet

# ------------------- Node Class -------------------
class Node:
    def __init__(self, name):
        self.name = name

# ------------------- Adaptive Encryption -------------------
def adaptive_encrypt(message, risk_score):
    """
    Choose encryption based on risk score
    """
    if risk_score > 0.7:
        # High risk → AES/Fernet
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted = f.encrypt(message.encode())
        return encrypted.decode('utf-8', 'ignore'), "Fernet-AES256"
    elif risk_score > 0.4:
        # Medium risk → simple ChaCha20 / AES128 (simulate with reversing + key)
        encrypted = message[::-1] + "||MEDIUM"
        return encrypted, "Medium-ChaCha20"
    else:
        # Low risk → simple reverse
        encrypted = message[::-1]
        return encrypted, "Simple-Reverse"

def adaptive_decrypt(encrypted_message, algo):
    if algo == "Fernet-AES256":
        return "[Encrypted message – key not stored for prototype]"
    elif algo == "Medium-ChaCha20":
        return encrypted_message.split("||")[0][::-1]
    else:
        return encrypted_message[::-1]

# ------------------- AI-based Risk Simulation -------------------
def simulate_risk(message):
    """
    Simple AI-like simulation: high risk if certain keywords exist
    """
    sensitive_keywords = ["secret", "confidential", "mission", "critical"]
    score = 0.2 + 0.8 * any(word in message.lower() for word in sensitive_keywords)
    # add some randomness
    score += random.uniform(0, 0.2)
    return min(score, 1.0)

# ------------------- Routing -------------------
def route_message(nodes, start, end):
    """
    Simulate random routing path
    """
    intermediates = [n for n in nodes if n != start and n != end]
    path_length = random.randint(1, min(3, len(intermediates)))
    path = [start] + random.sample(intermediates, path_length) + [end]
    return path

def visualize_path(path):
    G = nx.DiGraph()
    for i in range(len(path)-1):
        G.add_edge(path[i].name, path[i+1].name)
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=2000, node_color='skyblue', font_size=12, arrowsize=20)
    plt.show()

# ------------------- Sending Message -------------------
def send_message(message, nodes, start, end):
    print("\n=== Sending Message ===")
    print(f"Original Message: {message}")

    risk_score = simulate_risk(message)
    print(f"Risk Score: {risk_score:.2f}")

    path = route_message(nodes, start, end)
    print("Routing Path: " + " -> ".join([n.name for n in path]))

    encrypted_message, algo = adaptive_encrypt(message, risk_score)
    print(f"Encrypted with: {algo} -> {encrypted_message}")

    decrypted_message = adaptive_decrypt(encrypted_message, algo)
    print(f"Delivered Message: {decrypted_message}")

    # Visualize routing path
    visualize_path(path)

# ------------------- Demo -------------------
nodes = [Node(f"Node{i}") for i in range(1,6)]  # Node1 to Node5

# Demo messages
messages = [
    "Hello team, just a test",
    "Mission critical: proceed with caution",
    "Confidential: share only with Node2"
]

# Send messages
for msg in messages:
    send_message(msg, nodes, nodes[0], nodes[-1])
