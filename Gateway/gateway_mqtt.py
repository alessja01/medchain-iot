import json
import hmac
import hashlib
import os
import sqlite3
import paho.mqtt.client as mqtt
from crypto_utils import encrypt_aes_gcm_256, hash_sha256, encrypt_key_for_doctor
from blockchain_client import register_report_onchain



###################CONFIGURAZIONE MQTT
BROKER= "broker.hivemq.com" 
PORT=1883
TOPIC= "medchain/patient1" # topic dove l'esp32 pubblicherà i dati


###################CHIAVE HMAC
HMAC_KEY=b"supersecretHMACkey42"


######################CONGIG DB
DB_PATH="medchain.db"


#FUNZIONE DI SUPPORTO: STRINGA CANONICA
def build_canonical_string(device_id, timestamp, heart_rate, spo2, temperature):
    return f"{device_id}|{timestamp}|{heart_rate}|{spo2}|{temperature:.2f}"

#Callback quando il client MQTT si connette al broker
def on_connect(client, userdata, flags, rc):
    print("Connesso al broker MQTT, codice: ", rc)
    client.subscribe(TOPIC) #una vvolta connesso ci iscriviamo al topic
    print(f"Iscritto al topic: {TOPIC}")

def process_measurements(measurements: dict, raw_payload: str):
    # 1) Leggi campi dal JSON
    try:
        device_id   = measurements["deviceId"]
        timestamp   = measurements["timestamp"]
        heart_rate  = measurements["heartRate"]
        spo2        = measurements["spo2"]
        temperature = float(measurements["temperature"])
        hmac_recv   = measurements["hmac"]
    except KeyError as e:
        print("[ERRORE] Manca il campo JSON:", e)
        return

    print("\n[DATO] Misurazioni ricevute:")
    print(f"  deviceId    = {device_id}")
    print(f"  timestamp   = {timestamp}")
    print(f"  heartRate   = {heart_rate}")
    print(f"  spo2        = {spo2}")
    print(f"  temperature = {temperature}")
    print(f"  hmac (recv) = {hmac_recv}")

    # 2) Verifica HMAC (autenticità)
    canonical = build_canonical_string(
        device_id,
        timestamp,
        heart_rate,
        spo2,
        temperature
    )

    hmac_calc = hmac.new(
        HMAC_KEY,
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    print("\n[HMAC] Stringa firmata (gateway):", canonical)
    print("[HMAC] HMAC calcolato: ", hmac_calc)

    if not hmac.compare_digest(hmac_calc, hmac_recv):
        print("[ERRORE] HMAC NON VALIDO! Messaggio rifiutato ❌")
        return

    print("[HMAC] Firma valida. Messaggio autentico ✅")

    # 3) Genera chiave AES per questo report e cifra payload JSON
    plaintext = raw_payload.encode("utf-8")

    data_key = os.urandom(32)  # 32 byte = 256 bit
    nonce, ciphertext, tag = encrypt_aes_gcm_256(plaintext, data_key)

    # 3b) Cifra la data_key con la chiave pubblica del medico
    enc_key = encrypt_key_for_doctor(data_key, "doctor_public.pem")

    # 4) Hash del cifrato+tag (integrità / blockchain)
    hash_input = ciphertext + tag
    h = hash_sha256(hash_input)

    print("\n[CRITTO] AES-256-GCM COMPLETATO")
    print(f"         Hash SHA-256: {h}")

    # 5) Salva OFF-CHAIN (SQLite) SOLO cifrato + metadati
    row_id = save_report(
        device_id=device_id,
        timestamp=timestamp,
        hmac_recv=hmac_recv,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        enc_key=enc_key,
        hashed=h
    )
    print(f"[SQL] Salvato. offchainRef (id) = {row_id}")

    # 6) Salva ON-CHAIN (Blockchain) metadati + hash + offchainRef
    try:
        txh = register_report_onchain(
            device_id=device_id,
            timestamp=int(timestamp),
            hash_hex=h,
            offchain_ref=row_id,
            hmac_str=hmac_recv
        )
        print("[BLOCKCHAIN] Registrato on-chain:", txh)
    except Exception as e:
        print("[BLOCKCHAIN][ERRORE] Registrazione on-chain fallita:", e)


# Callback quando arriva un messaggio MQTT
def on_message(client, userdata, msg):
    payload_str = msg.payload.decode("utf-8", errors="ignore")
    print(f"\n[MQTT] Messaggio ricevuto su {msg.topic}: {payload_str}")

    try:
        measurements = json.loads(payload_str)
    except json.JSONDecodeError:
        print("[ERRORE] Payload non è JSON valido")
        return

    process_measurements(measurements, payload_str)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            hmac TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL,
            enc_key BLOB NOT NULL,
            hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()
    print("[SQL] tabella 'reports' pronta")

def save_report(device_id, timestamp, hmac_recv,
                nonce, ciphertext, tag, enc_key, hashed):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO reports
        (device_id, timestamp, hmac, nonce, ciphertext, tag, enc_key, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        device_id,
        int(timestamp),
        hmac_recv,
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


def main():
    init_db()

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    print("Mi collego al broker MQTT ...")
    client.connect(BROKER, PORT, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()