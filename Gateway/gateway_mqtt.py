# =========================
# gateway_mqtt.py (Ed25519 + Challenge/Response + ACK firmato)
# =========================

import json
import os
import time
import secrets
import sqlite3
import paho.mqtt.client as mqtt

# Ed25519 (PyNaCl)
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

# funzioni crittografiche locali (AES-GCM, hash, RSA per data_key)
from crypto_utils import encrypt_aes_gcm_256, hash_sha256, encrypt_key_for_doctor

# chiamata per registrare hash su blockchain (Hardhat/contract)
from blockchain_client import register_report_onchain


# =========================
# CONFIG MQTT
# =========================

BROKER = "broker.hivemq.com"
PORT = 8883

TOPIC_VITALS = "medchain/patient1"        # VITALS (device -> gateway)
TOPIC_REG    = "medchain/register"        # REGISTER (device -> gateway)
TOPIC_PROOF  = "medchain/register/proof"  # PROOF (device -> gateway)

# =========================
# DB
# =========================
DB_PATH = "medchain.db"


# =========================
# CANONICAL STRING (DEVONO MATCHARE ARDUINO)
# =========================

def build_canonical_string_register(device_id: str, timestamp: int, counter: int, pubkey_hex: str) -> str:
    # Arduino firma REGISTER:
    # "REGISTER|deviceId|ts|counter|pubKeyHex"
    return f"REGISTER|{device_id}|{timestamp}|{counter}|{pubkey_hex}"

def build_canonical_string_proof(device_id: str, nonce_hex: str, timestamp: int, counter: int) -> str:
    # Arduino firma PROOF:
    # "PROOF|deviceId|nonce|ts|counter"
    return f"PROOF|{device_id}|{nonce_hex}|{timestamp}|{counter}"

def build_canonical_string_ack(device_id: str, timestamp: int, status: str, nonce_hex: str) -> str:
    # Gateway firma ACK:
    # "ACK|deviceId|ts|status|nonce"
    return f"ACK|{device_id}|{timestamp}|{status}|{nonce_hex}"

def build_canonical_string_vitals(device_id: str, timestamp: int, counter: int, heart_rate: int, spo2: int, temperature_centi: int) -> str:
    # Arduino firma VITALS:
    # "VITALS|deviceId|ts|counter|hr|spo2|tempCenti"
    return f"VITALS|{device_id}|{timestamp}|{counter}|{heart_rate}|{spo2}|{temperature_centi}"


# =========================
# GATEWAY KEYPAIR (PERSISTENTE) per firmare ACK
# =========================

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def load_or_create_gateway_keys():
    """
    Genera una volta la chiave privata del gateway e la salva su file.
    Così la pubkey del gateway resta sempre la stessa (importante per Arduino).
    """
    sk_path = "gateway_sk.hex"
    pk_path = "gateway_pk.hex"

    if os.path.exists(sk_path) and os.path.exists(pk_path):
        sk_hex = open(sk_path, "r").read().strip()
        pk_hex = open(pk_path, "r").read().strip()
        sk = SigningKey(hex_to_bytes(sk_hex))
        return sk, pk_hex

    sk = SigningKey.generate()
    pk_hex = bytes_to_hex(sk.verify_key.encode())

    open(sk_path, "w").write(bytes_to_hex(sk.encode()))
    open(pk_path, "w").write(pk_hex)

    return sk, pk_hex

GATEWAY_SK, GATEWAY_PUBKEY_HEX = load_or_create_gateway_keys()

print("\n=== COPIA QUESTA STRINGA NEL CODICE ARDUINO (GATEWAY_PUBKEY_HEX) ===")
print(GATEWAY_PUBKEY_HEX)
print("====================================================================\n")


def gateway_sign_hex(canonical: str) -> str:
    sig = GATEWAY_SK.sign(canonical.encode("utf-8")).signature
    return bytes_to_hex(sig)


def ed25519_verify(pubkey_hex: str, canonical: str, sig_hex: str) -> bool:
    try:
        vk = VerifyKey(hex_to_bytes(pubkey_hex))
        vk.verify(canonical.encode("utf-8"), hex_to_bytes(sig_hex))
        return True
    except BadSignatureError:
        return False
    except Exception:
        return False


# =========================
# DB INIT + SAVE
# =========================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # report cifrati + metadati + hash
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            sig TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL,
            enc_key BLOB NOT NULL,
            hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # anti-replay: ultimo counter visto
    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_state (
            device_id TEXT PRIMARY KEY,
            last_counter INTEGER NOT NULL
        );
    """)

    # NUOVO: tabella dispositivi (pubKey + provisioned)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            pubkey_hex TEXT NOT NULL,
            provisioned INTEGER NOT NULL DEFAULT 0
        );
    """)

    # NUOVO: challenge pending
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_challenge (
            device_id TEXT PRIMARY KEY,
            nonce_hex TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
    """)

    conn.commit()
    conn.close()
    print("[SQL] tabelle pronte: reports, device_state, devices, pending_challenge")


def save_report(device_id, timestamp, sig_recv, nonce, ciphertext, tag, enc_key, hashed):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO reports
        (device_id, timestamp, sig, nonce, ciphertext, tag, enc_key, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        device_id,
        int(timestamp),
        sig_recv,
        sqlite3.Binary(nonce),
        sqlite3.Binary(ciphertext),
        sqlite3.Binary(tag),
        sqlite3.Binary(enc_key),
        hashed
    ))

    conn.commit()
    row_id = cur.lastrowid
    conn.close()

    print(f"[SQL] Report salvato con id={row_id}")
    return row_id


def check_and_update_counter(device_id: str, counter: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT last_counter FROM device_state WHERE device_id=?", (device_id,))
    row = cur.fetchone()

    if row is not None:
        last_counter = int(row[0])
        if counter <= last_counter:
            conn.close()
            return False

    cur.execute("""
        INSERT INTO device_state(device_id, last_counter)
        VALUES (?, ?)
        ON CONFLICT(device_id) DO UPDATE SET last_counter=excluded.last_counter
    """, (device_id, counter))

    conn.commit()
    conn.close()
    return True


# ===== devices table helpers =====
def upsert_device(device_id: str, pubkey_hex: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO devices(device_id, pubkey_hex, provisioned)
        VALUES (?, ?, 0)
        ON CONFLICT(device_id) DO UPDATE SET pubkey_hex=excluded.pubkey_hex
    """, (device_id, pubkey_hex))
    conn.commit()
    conn.close()

def set_provisioned(device_id: str, value: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE devices SET provisioned=? WHERE device_id=?", (value, device_id))
    conn.commit()
    conn.close()

def get_device(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT device_id, pubkey_hex, provisioned FROM devices WHERE device_id=?", (device_id,))
    row = cur.fetchone()
    conn.close()
    return row


# ===== pending challenge helpers =====
def set_pending(device_id: str, nonce_hex: str, expires_at: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pending_challenge(device_id, nonce_hex, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET nonce_hex=excluded.nonce_hex, expires_at=excluded.expires_at
    """, (device_id, nonce_hex, expires_at))
    conn.commit()
    conn.close()

def get_pending(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT nonce_hex, expires_at FROM pending_challenge WHERE device_id=?", (device_id,))
    row = cur.fetchone()
    conn.close()
    return row

def clear_pending(device_id: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM pending_challenge WHERE device_id=?", (device_id,))
    conn.commit()
    conn.close()


# =========================
# MQTT: publish helpers
# =========================

def send_challenge(client: mqtt.Client, device_id: str):
    # nonce casuale: 16 byte -> 32 char hex
    nonce_hex = secrets.token_hex(16)
    expires_at = int(time.time()) + 60  # valido 60 secondi
