# 🩺 MedChain IoT

**MedChain IoT** è un sistema di monitoraggio medico basato su **IoT, crittografia avanzata e Blockchain**, progettato per garantire **integrità, autenticità, confidenzialità e tracciabilità** dei dati clinici raccolti da dispositivi IoT.

Il sistema separa in modo netto:
- **dati sensibili** → cifrati e conservati **off-chain**
- **prove crittografiche** → registrate **on-chain**

In questo modo la blockchain certifica i dati **senza mai memorizzare informazioni sanitarie in chiaro**.

---

## 📖 Descrizione del progetto

MedChain IoT nasce per affrontare uno dei problemi centrali della sanità digitale:

> **Come fidarsi dei dati clinici generati da dispositivi IoT?**

Il progetto garantisce che:
- i dati provengano da un dispositivo autentico
- i dati non possano essere alterati
- ogni report sia verificabile nel tempo
- la privacy del paziente sia sempre preservata

---

## 🎯 Obiettivi principali

Il sistema permette di:

- raccogliere parametri vitali in tempo reale  
- prevenire spoofing e falsificazione dei dati  
- autenticare crittograficamente i dispositivi IoT  
- proteggere i dati clinici con cifratura forte  
- certificare l’integrità dei report tramite blockchain  
- consentire al paziente il controllo degli accessi  

📌 **Nessun dato clinico viene mai scritto in chiaro sulla blockchain.**

---

## 🧩 Tecnologie utilizzate

### 🔧 Hardware
- Arduino R4 WiFi / ESP32  
- Sensori medicali (battito cardiaco, SpO₂, temperatura)

### 💻 Software & Sicurezza
- **Comunicazione**: MQTT su TLS (MQTTS)  
- **Firma digitale**: Ed25519 (device e gateway)  
- **Cifratura dati**: AES-256-GCM  
- **Protezione chiavi**: RSA-OAEP (chiave del medico)  
- **Hashing**: SHA-256  
- **Anti-replay**: counter monotono + timestamp  

### ⛓️ Blockchain
- Smart contract Ethereum (Hardhat)
- Registrazione di:
  - hash dei dati cifrati
  - deviceID (hashato)
  - timestamp
  - riferimento allo storage off-chain
- Nessun dato sensibile on-chain

---

## 🏗️ Architettura del sistema

```text
[ IoT Device ]
     |
     |  (Ed25519 + TLS)
     v
[ Gateway Sicuro ]
     |
     |  (AES-GCM + RSA)
     v
[ Storage Off-chain ] -----> [ Blockchain ]


---

## Cose da modificare
 comunicazione non è 8883
 timestamp inizializzato a cazzo e non dev'essere così 
 ho tolto tanti controlli in on_connect di gateway da rimettere
 