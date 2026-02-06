# =========================
# gateway_mqtt_ed25519.py
# =========================
# Funzionalità:
# - Verifica firme Ed25519 dal device (REGISTER / PROOF / VITALS)
# - Provisioning challenge–response
# - ACK firmato dal gateway (Ed25519)
# - Anti-replay robusto: counter + finestra timestamp + last_timestamp
# - Cifratura AES-256-GCM del payload VITALS (off-chain)
# - Cifratura data_key per medico (RSA-OAEP)
# - Hash SHA-256(nonce||ciphertext||tag)
# - Firma gateway del REPORT e salvataggio:
#     - DB: gateway_sig (firma completa) + gateway_sig_hash (bytes32 hex)
#     - On-chain: gateway_sig_hash (bytes32)
# - ✅ Affidabilità: Retry Queue per blockchain (pending_chain + worker retry)
#
# Dipendenze:
#   pip install paho-mqtt pynacl web3 cryptography
#
# File richiesti:
#   - crypto_utils.py (il tuo)
#   - blockchain_client.py (aggiornato con gateway_sig_hash_hex)
#   - doctor_public.pem

import json
import os
import time
import secrets
import sqlite3
import threading

import paho.mqtt.client as mqtt
from web3 import Web3

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from crypto_utils import encrypt_aes_gcm_256, hash_sha256, encrypt_key_for_doctor
from blockchain_client import register_report_onchain


# =========================
# CONFIG MQTT
# =========================
BROKER = "broker.hivemq.com"
PORT = 8883

TOPIC_VITALS = "medchain/patient1"        # device -> gateway
TOPIC_REG    = "medchain/register"        # device -> gateway
TOPIC_PROOF  = "medchain/register/proof"  # device -> gateway

# =========================
# SICUREZZA TIMESTAMP
# =========================
MAX_TS_SKEW_SEC = 120  # accetta timestamp entro ±120s dall'orologio gateway

# =========================
# RETRY QUEUE BLOCKCHAIN
# =========================
RETRY_INTERVAL_SEC = 30     # ogni quanto riprovare
RETRY_BATCH_SIZE = 5        # quanti job per ciclo
RETRY_MAX_ATTEMPTS = 10     # massimo tentativi per job

# =========================
# DB
# =========================
DB_PATH = "medchain.db"


# =========================
# HEX utils
# =========================
def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def bytes_to_hex(b: bytes) -> str:
    return b.hex()


# =========================
# CANONICAL STRINGS (DEVONO MATCHARE ARDUINO)
# =========================
def canonical_register(device_id: str, ts: int, counter: int, pubkey_hex: str) -> str:
    return f"REGISTER|{device_id}|{ts}|{counter}|{pubkey_hex}"

def canonical_proof(device_id: str, nonce_hex: str, ts: int, counter: int) -> str:
    return f"PROOF|{device_id}|{nonce_hex}|{ts}|{counter}"

def canonical_ack(device_id: str, ts: int, status: str, nonce_hex: str) -> str:
    return f"ACK|{device_id}|{ts}|{status}|{nonce_hex}"

def canonical_vitals(device_id: str, ts: int, counter: int, hr: int, spo2: int, temp_centi: int) -> str:
    return f"VITALS|{device_id}|{ts}|{counter}|{hr}|{spo2}|{temp_centi}"

# ✅ Firma gateway su report cifrato (audit/non-ripudio)
def canonical_report(device_id: str, ts: int, hash_hex: str, offchain_ref: int) -> str:
    return f"REPORT|{device_id}|{ts}|{hash_hex}|{offchain_ref}"


# =========================
# GATEWAY KEYPAIR (Ed25519) PERSISTENTE
# =========================
def load_or_create_gateway_keys():
    """
    Genera una volta la chiave privata del gateway e la salva su file.
    Così la pubkey gateway resta stabile da copiare nel device (Arduino).
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
print("\n=== COPIA QUESTA STRINGA NEL DEVICE (GATEWAY_PUBKEY_HEX) ===")
print(GATEWAY_PUBKEY_HEX)
print("============================================================\n")


def gateway_sign_hex(canonical: str) -> str:
    sig = GATEWAY_SK.sign(canonical.encode("utf-8")).signature  # 64 bytes
    return bytes_to_hex(sig)  # 128 char hex


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
# DB INIT + HELPERS
# =========================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ✅ REPORTS: tabella che nel tuo snippet mancava (ma la usi in INSERT)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,

            device_sig TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL,
            enc_key BLOB NOT NULL,
            hash TEXT NOT NULL,

            gateway_sig TEXT NOT NULL,
            gateway_sig_hash TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # ✅ Retry queue blockchain
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_chain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            hash_ciphertext TEXT NOT NULL,
            gateway_sig_hash TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # stato device per anti-replay robusto
    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_state (
            device_id TEXT PRIMARY KEY,
            last_counter INTEGER NOT NULL DEFAULT 0,
            last_timestamp INTEGER NOT NULL DEFAULT 0
        );
    """)

    # registry device: pubkey + provisioned
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            pubkey_hex TEXT NOT NULL,
            provisioned INTEGER NOT NULL DEFAULT 0
        );
    """)

    # challenge pending
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_challenge (
            device_id TEXT PRIMARY KEY,
            nonce_hex TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
    """)

    conn.commit()
    conn.close()
    print("[SQL] DB pronto: reports, pending_chain, device_state, devices, pending_challenge")


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


def check_and_update_state(device_id: str, counter: int, ts: int) -> bool:
    """
    Anti-replay robusto:
    - timestamp deve essere entro finestra (±MAX_TS_SKEW_SEC)
    - counter deve crescere
    - timestamp non deve tornare indietro (>= last_timestamp)
    """
    now = int(time.time())

    if ts < now - MAX_TS_SKEW_SEC or ts > now + MAX_TS_SKEW_SEC:
        return False

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT last_counter, last_timestamp FROM device_state WHERE device_id=?", (device_id,))
    row = cur.fetchone()

    last_counter = 0
    last_ts = 0
    if row is not None:
        last_counter = int(row[0])
        last_ts = int(row[1])

        if counter <= last_counter:
            conn.close()
            return False
        if ts < last_ts:
            conn.close()
            return False

    cur.execute("""
        INSERT INTO device_state(device_id, last_counter, last_timestamp)
        VALUES (?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
          last_counter=excluded.last_counter,
          last_timestamp=excluded.last_timestamp
    """, (device_id, counter, ts))

    conn.commit()
    conn.close()
    return True


# =========================
# RETRY QUEUE: ENQUEUE + WORKER
# =========================
def enqueue_chain_retry(report_id: int, device_id: str, ts: int, hash_hex: str, gateway_sig_hash_hex: str, error: Exception):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pending_chain
        (report_id, device_id, timestamp, hash_ciphertext, gateway_sig_hash, last_error)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (report_id, device_id, int(ts), hash_hex, gateway_sig_hash_hex, str(error)))
    conn.commit()
    conn.close()
    print(f"[RETRY] enqueue report_id={report_id} err={error}")


def retry_pending_onchain():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, report_id, device_id, timestamp, hash_ciphertext, gateway_sig_hash, attempts
        FROM pending_chain
        WHERE attempts < ?
        ORDER BY created_at
        LIMIT ?
    """, (RETRY_MAX_ATTEMPTS, RETRY_BATCH_SIZE))
    rows = cur.fetchall()

    if not rows:
        conn.close()
        return

    print(f"[RETRY] trovati {len(rows)} job da ritentare...")

    for pid, report_id, device_id, ts, h, gsh, attempts in rows:
        try:
            txh = register_report_onchain(
                device_id_str=device_id,
                timestamp=int(ts),
                hash_hex=h,
                offchain_ref=int(report_id),
                gateway_sig_hash_hex=gsh
            )
            print(f"[RETRY] SUCCESS pid={pid} tx={txh}")
            cur.execute("DELETE FROM pending_chain WHERE id=?", (pid,))
        except Exception as e:
            print(f"[RETRY] FAIL pid={pid} attempt={attempts+1} err={e}")
            cur.execute("""
                UPDATE pending_chain
                SET attempts = attempts + 1,
                    last_error = ?
                WHERE id = ?
            """, (str(e), pid))

    conn.commit()
    conn.close()


def retry_loop():
    while True:
        time.sleep(RETRY_INTERVAL_SEC)
        try:
            retry_pending_onchain()
        except Exception as e:
            print("[RETRY] loop error:", e)


# =========================
# MQTT publish helpers
# =========================
def send_challenge(client: mqtt.Client, device_id: str):
    nonce_hex = secrets.token_hex(16)
    expires_at = int(time.time()) + 60

    set_pending(device_id, nonce_hex, expires_at)

    topic = f"medchain/challenge/{device_id}"
    payload = {"type": "CHALLENGE", "deviceId": device_id, "nonce": nonce_hex, "expiresAt": expires_at}
    client.publish(topic, json.dumps(payload))
    print(f"[CHALLENGE] -> {topic} nonce={nonce_hex}")


def send_ack_signed(client: mqtt.Client, device_id: str, nonce_hex: str, status: str = "OK"):
    ts = int(time.time())
    canon = canonical_ack(device_id, ts, status, nonce_hex)
    sig_hex = gateway_sign_hex(canon)

    topic = f"medchain/register/ack/{device_id}"
    payload = {
        "type": "ACK",
        "deviceId": device_id,
        "timestamp": ts,
        "status": status,
        "nonce": nonce_hex,
        "sig": sig_hex
    }
    client.publish(topic, json.dumps(payload))
    print(f"[ACK] firmato -> {topic} status={status}")


# =========================
# PROCESSING
# =========================
def process_register(client: mqtt.Client, m: dict):
    try:
        device_id = m["deviceId"]
        ts = int(m["timestamp"])
        counter = int(m["counter"])
        pubkey_hex = m["pubKey"]
        sig_hex = m["sig"]
    except (KeyError, ValueError, TypeError) as e:
        print("[REGISTER][ERR] campi non validi:", e)
        return

    canon = canonical_register(device_id, ts, counter, pubkey_hex)
    if not ed25519_verify(pubkey_hex, canon, sig_hex):
        print("[REGISTER] firma NON valida ❌", device_id)
        return

    print("[REGISTER] firma valida ✅", device_id)
    upsert_device(device_id, pubkey_hex)
    send_challenge(client, device_id)


def process_proof(client: mqtt.Client, m: dict):
    try:
        device_id = m["deviceId"]
        nonce_hex = m["nonce"]
        ts = int(m["timestamp"])
        counter = int(m["counter"])
        sig_hex = m["sig"]
    except (KeyError, ValueError, TypeError) as e:
        print("[PROOF][ERR] campi non validi:", e)
        return

    dev = get_device(device_id)
    if not dev:
        print("[PROOF] device sconosciuto:", device_id)
        return

    _, pubkey_hex, _prov = dev

    pend = get_pending(device_id)
    if not pend:
        print("[PROOF] nessuna challenge pending:", device_id)
        return

    expected_nonce, expires_at = pend
    if int(time.time()) > int(expires_at):
        print("[PROOF] challenge scaduta:", device_id)
        clear_pending(device_id)
        return

    if nonce_hex != expected_nonce:
        print("[PROOF] nonce mismatch:", device_id)
        return

    canon = canonical_proof(device_id, nonce_hex, ts, counter)
    if not ed25519_verify(pubkey_hex, canon, sig_hex):
        print("[PROOF] firma NON valida ❌", device_id)
        return

    print("[PROOF] firma valida ✅ -> provisioned", device_id)
    set_provisioned(device_id, 1)
    clear_pending(device_id)
    send_ack_signed(client, device_id, nonce_hex, status="OK")


def process_vitals(m: dict, raw_payload: str):
    try:
        device_id = m["deviceId"]
        ts = int(m["timestamp"])
        counter = int(m["counter"])
        hr = int(m["heartRate"])
        spo2 = int(m["spo2"])
        temp = int(m["temperature"])
        device_sig_hex = m["sig"]
    except (KeyError, ValueError, TypeError) as e:
        print("[VITALS][ERR] campi non validi:", e)
        return

    dev = get_device(device_id)
    if not dev:
        print("[VITALS] device sconosciuto:", device_id)
        return

    _, pubkey_hex, provisioned = dev
    if int(provisioned) != 1:
        print("[VITALS] device non provisioned -> scarto ❌", device_id)
        return

    canon = canonical_vitals(device_id, ts, counter, hr, spo2, temp)
    if not ed25519_verify(pubkey_hex, canon, device_sig_hex):
        print("[VITALS] firma device NON valida ❌", device_id)
        return

    if not check_and_update_state(device_id, counter, ts):
        print("[REPLAY/TIME] counter/timestamp non valido -> scarto ❌", device_id)
        return

    print("[VITALS] firma valida ✅ + anti-replay OK", device_id)

    plaintext = raw_payload.encode("utf-8")
    data_key = os.urandom(32)

    nonce, ciphertext, tag = encrypt_aes_gcm_256(plaintext, data_key)
    enc_key = encrypt_key_for_doctor(data_key, "doctor_public.pem")
    h = hash_sha256(nonce + ciphertext + tag)

    # Salvataggio off-chain con placeholder firma gateway (poi update)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO reports
        (device_id, timestamp, device_sig, nonce, ciphertext, tag, enc_key, hash, gateway_sig, gateway_sig_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        device_id,
        int(ts),
        device_sig_hex,
        sqlite3.Binary(nonce),
        sqlite3.Binary(ciphertext),
        sqlite3.Binary(tag),
        sqlite3.Binary(enc_key),
        h,
        "PENDING",
        "PENDING"
    ))
    conn.commit()
    row_id = cur.lastrowid

    # Firma gateway del report (include offchainRef=row_id)
    rep_canon = canonical_report(device_id, ts, h, row_id)
    gateway_sig_hex = gateway_sign_hex(rep_canon)
    gateway_sig_hash_hex = Web3.keccak(hexstr="0x" + gateway_sig_hex).hex()[2:]

    # aggiorna firma reale
    cur.execute("""
        UPDATE reports
        SET gateway_sig=?, gateway_sig_hash=?
        WHERE id=?
    """, (gateway_sig_hex, gateway_sig_hash_hex, row_id))
    conn.commit()
    conn.close()

    print(f"[SQL] Report salvato id={row_id}")
    print(f"[AUDIT] gateway_sig_hash={gateway_sig_hash_hex}")

    # ON-CHAIN: se fallisce -> retry queue
    try:
        txh = register_report_onchain(
            device_id_str=device_id,
            timestamp=ts,
            hash_hex=h,
            offchain_ref=row_id,
            gateway_sig_hash_hex=gateway_sig_hash_hex
        )
        print("[BLOCKCHAIN] Registrato on-chain:", txh)
    except Exception as e:
        print("[BLOCKCHAIN] fallita, metto in retry queue ❌", e)
        enqueue_chain_retry(
            report_id=row_id,
            device_id=device_id,
            ts=ts,
            hash_hex=h,
            gateway_sig_hash_hex=gateway_sig_hash_hex,
            error=e
        )


# =========================
# MQTT CALLBACKS
# =========================
def on_connect(client, userdata, flags, rc):
    print("[MQTT] Connesso, rc=", rc)
    client.subscribe(TOPIC_REG)
    client.subscribe(TOPIC_PROOF)
    client.subscribe(TOPIC_VITALS)
    print("[MQTT] Subscribed:", TOPIC_REG, TOPIC_PROOF, TOPIC_VITALS)


def on_message(client, userdata, msg):
    payload_str = msg.payload.decode("utf-8", errors="ignore")
    print(f"\n[MQTT] {msg.topic} -> {payload_str}")

    try:
        m = json.loads(payload_str)
    except json.JSONDecodeError:
        print("[MQTT][ERR] payload non JSON")
        return

    mtype = m.get("type", "")

    if mtype == "REGISTER":
        process_register(client, m)
    elif mtype == "PROOF":
        process_proof(client, m)
    elif mtype == "VITALS":
        process_vitals(m, payload_str)
    else:
        print("[MQTT] type sconosciuto:", mtype)


# =========================
# MAIN
# =========================
def main():
    init_db()

    # ✅ avvia worker retry in background
    threading.Thread(target=retry_loop, daemon=True).start()
    print(f"[RETRY] worker attivo (ogni {RETRY_INTERVAL_SEC}s)")

    client = mqtt.Client(client_id="medchain-gateway-ed25519")
    client.on_connect = on_connect
    client.on_message = on_message

    client.tls_set()
    client.tls_insecure_set(False)

    print("[MQTT] Connessione TLS a broker...")
    client.connect(BROKER, PORT, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()
