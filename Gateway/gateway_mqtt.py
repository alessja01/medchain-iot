import json
import hmac
import hashlib
import sqlite3
import paho.mqtt.client as mqtt
from crypto_utils import encrypt_aes_gcm_256, hash_sha256


###################CONFIGURAZIONE MQTT
BROKER= "broker.hivemq.com" 
PORT=1883
TOPIC= "medchain/patient1" # topic dove l'esp32 pubblicherà i dati


###################CHIAVE HMAC
HMAC_KEY=b"supersecretHMACkey42"


####################CHIAVE AES-256 (32 byte)
AES_KEY=bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "00112233445566778899aabbccddeeff"
)

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
    try:
        device_id= measurements["deviceId"]
        timestamp= measurements["timestamp"]
        heart_rate= measurements["heartRate"]
        spo2= measurements["spo2"]
        temperature=measurements["temperature"]
        hmac_recv=measurements["hmac"]
    except KeyError as e:
        print("[ERRORE] Manca il campo JSON:",e)
        return
    

    print("\n[DATO] Misurazioni ricevute:")
    print(f"  deviceId    = {device_id}")
    print(f"  timestamp   = {timestamp}")
    print(f"  heartRate   = {heart_rate}")
    print(f"  spo2        = {spo2}")
    print(f"  temperature = {temperature}")
    print(f"  hmac (recv) = {hmac_recv}")

    # Ricostruisco la stringa CANONICA come su ESP32
    canonical = build_canonical_string(
        device_id,
        timestamp,
        heart_rate,
        spo2,
        float(temperature)
    )

    # Ricalcolo HMAC lato gateway
    hmac_calc = hmac.new(
        HMAC_KEY,
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    print("\n[HMAC] Stringa firmata (gateway):", canonical)
    print("[HMAC] HMAC calcolato: ", hmac_calc)

    #Confronto: se diverso → messaggio NON autentico
    if not hmac.compare_digest(hmac_calc, hmac_recv):
        print("[ERRORE] HMAC NON VALIDO! Messaggio rifiutato ")
        return
    else:
        print("[HMAC] Firma valida. Messaggio autentico ")

    # --- DA QUI IN GIÙ: dato considerato autentico ---

    #Cifratura AES-256-GCM del JSON completo
    plaintext = raw_payload.encode("utf-8")
    nonce, ciphertext, tag = encrypt_aes_gcm_256(plaintext, AES_KEY)

    #Calcolo hash del cifrato + tag (per la blockchain)
    hash_input = ciphertext + tag
    h = hash_sha256(hash_input)

    print("\n[CRITTO] AES-256-GCM COMPLETATO")
    print(f"         Hash SHA-256: {h}")
    print(f"         Nonce (hex):      {nonce.hex()}")
    print(f"         Ciphertext (hex): {ciphertext.hex()}")
    print(f"         Tag (hex):        {tag.hex()}")

    row_id = save_report(
        device_id, timestamp, heart_rate, spo2, temperature,
        hmac_recv, nonce, ciphertext, tag, h
    )
    print("\n[SQL] Report salvato correttamente nel database.")
    print(f"[INFO] offchainRef potrà essere l'id={row_id} nella blockchain.")




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
    conn=sqlite3.connect(DB_PATH)
    cur= conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            heart_rate INTEGER,
            spo2 INTEGER,
            temperature REAL,
            hmac TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL,
            hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP    
                );
    """)
    conn.commit()
    conn.close()
    print("[SQL] tabella 'reports' pronta")

def save_report(device_id, timestamp, heart_rate, spo2, temperature,
                hmac_recv, nonce, ciphertext, tag, hashed):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO reports
        (device_id, timestamp, heart_rate, spo2, temperature,
         hmac, nonce, ciphertext, tag, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        device_id,
        int(timestamp),
        int(heart_rate),
        int(spo2),
        float(temperature),
        hmac_recv,
        nonce,
        ciphertext,
        tag,
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