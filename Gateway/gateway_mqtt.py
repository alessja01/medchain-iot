import json 
import paho.mqtt.client as mqtt

from crypto_utils import encrypt_aes_gcm_256, hash_sha256

#configurazione MQTT

BROKER= "broker.hivemq.com" 
PORT=1883
TOPIC= "medchain/patient1" # topic dove l'esp32 pubblicherà i dati


#Callback quando il client MQTT si connette al broker
def on_connect(client, userdata, flags, rc):
    print("Connesso al broker MQTT, codice: ", rc)
    client.subscribe(TOPIC) #una vvolta connesso ci iscriviamo al topic
    print(f"Iscritto al topic: {TOPIC}")

def process_measurements(measurements: dict, raw_payload: str):
   
    plaintext = raw_payload.encode("utf-8")
    key, nonce, ciphertext = encrypt_aes_gcm_256(plaintext)

    h = hash_sha256(ciphertext)

    print("[CRITTO] AES-256-GCM COMPLETATO")
    print(f"         Hash SHA-256: {h}")
    print(f"         Key (hex): {key.hex()}")
    print(f"         Nonce (hex): {nonce.hex()}")
    print(f"         Ciphertext (hex): {ciphertext.hex()}")



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


def main():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    print("Mi collego al broker MQTT ...")
    client.connect(BROKER, PORT, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()