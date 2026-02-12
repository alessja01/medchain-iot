import sqlite3
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256

DB_PATH = "medchain.db"
PRIVATE_KEY_FILE = "doctor_private.pem"

def to_bytes(x):
    if x is None:
        return None
    if isinstance(x, memoryview):
        return x.tobytes()
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return bytes.fromhex(x)
    raise TypeError(f"Tipo non gestito: {type(x)}")

def decrypt_data(ciphertext, nonce, tag, enc_key_rsa, private_key_path):
    # 1) chiave privata medico
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    # 2) RSA-OAEP con SHA-256 (deve matchare il gateway!)
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    aes_key = cipher_rsa.decrypt(enc_key_rsa)

    # 3) AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")

def view_reports(limit=5):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, device_id, timestamp, nonce, ciphertext, tag, enc_key
        FROM reports
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()

    if not rows:
        print("Database vuoto.")
        return

    for r_id, dev_id, ts, nonce, ct, tag, enc_key in rows:
        print(f"\nReport ID: {r_id} | Device: {dev_id} | ts={ts}")

        try:
            nonce_b = to_bytes(nonce)
            ct_b = to_bytes(ct)
            tag_b = to_bytes(tag)
            enc_key_b = to_bytes(enc_key)

            decrypted_json = decrypt_data(ct_b, nonce_b, tag_b, enc_key_b, PRIVATE_KEY_FILE)
            data = json.loads(decrypted_json)

            print("  [STATO] Decriptazione: SUCCESSO ✅")
            print(f"  [DATI] BPM: {data['heartRate']} | SpO2: {data['spo2']}% | Temp: {data['temperature']/100.0}°C")

        except Exception as e:
            print("  [STATO] Decriptazione: FALLITA ❌")
            print("  [DEBUG ERRORE]", repr(e))

    conn.close()

if __name__ == "__main__":
    view_reports()
