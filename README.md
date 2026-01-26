#🩺 MEDCHAIN IOT
MedChain IoT è un sistema di monitoraggio medico basato su IOT e Blockchain che consente la raccolta, proiezione e la verifica dei dati clinici dei pazienti, garantendo integrità, autenticità e confidenzialità delle informazioni sanitarie.
Il progetto utilizza dispositivi IOT (ESP32/ Arduino con sensori medici) per la misurazione dei parametri vitali e una blockchain per certificare l'origine e l'immutabilità dei dati, senza memorizzare informazioni sensibili on-chain
-----
## 📖 Descrizione del progetto 
Medchain IOT nasce con l'obiettivo di risolvere uno dei principali problemi della sanità digitale: 
** la fiducia nei dati clinici raccolti da dispositivi IOT **.

Il sistema permette di:
-raccogliere parametri medici in tempi reale
-impedisce la falsificazione dei dati 
-garantire che ogni dato provenga da un dispositivo autorizzato 
-consentire al paziente di controllare l'accesso ai propri dati 
-verificare l'integrità dei report tramite blockchain

i dati clinici ** non vengono mai salvati in chiaro sulla blockchain**, ma vengono cifrati e archiviati off-chain, mentre la blockchain conserva solo metadati certificati

----
## Tecnologie Utilizzate
### Hardware : 
-Esp32
### Software:
-comunicazione: HTTPS
-Crittografia: 
    -AES-256-GCM (simmetrica)
-Hashing: SHA-256
-Firma digitale: chiavi crittografiche del dispositivo 

### Blockchain:
-Smart Contract per: 
    - verifica firme digitali
    - registrazione dei metadati 
    - gestione degli accessi medico paziente
-Storage off-chian

----

## Architettura e Funzionamento 

### 1 Raccolta dei dati medici (IOT):
il dispositivo IOT rileva in tempo reale:
-battito cardiaco
-ossigenazione (Sp02)

ad ogni misurazione include:
-timestamp locale
- identificativo del dispositivo (deviceID)

---
### 2 Autenticità e origine del dato:
Per evitare manomissioni o spoofing:
-il dispositivo genera un timestamp
-firma i dati grezzi (o il loro hash)
-invia i dati al gateway tramite connessione sicura (TLS)

--- 
### 3 Cifratura dei dati (Gateway)
Il gateway riceve i dati e applica cifratura forte per garantire la confidenzialità:

dati_cifrati = Encrypt(chiave_medico/paziente, dati)

Possibili approcci:
-cifratura simmetrica (AES-256-GCM)
-cifratura asimmetrica (ECC/ RSA con chiave del medico)

---
### 4 Firma digitale finale del report 
Dopo la cifratura:
1. viene calcolato l'hash dei dati cifrati 
2. viene generata la firma digitale finale

hash= SHA-256(dati_cifrati)
firma=Sign(chiave_privata_device, hash)

Garantire che il dato non sia stato modificato dopo la cifratura
La Blockchain potrà verificarne l'autenticità

---

## 🔗 Ruolo della Blockchain

### 📌 1. Memorizzazione di metadati non sensibili
La blockchain registra esclusivamente:
- hash dei dati cifrati
- deviceID
- timestamp
- firma digitale
- riferimento allo storage off-chain (es. IPFS hash)

---

### 📌 2. Garanzia di integrità e autenticità
Grazie a hash e firme digitali, è possibile verificare che:
- il dato provenga da un dispositivo autorizzato
- non sia stato alterato
- sia stato registrato in uno specifico momento temporale

---

### 📌 3. Gestione degli accessi (medico ↔ paziente)
Lo smart contract implementa:
- concessione e revoca dei permessi da parte del paziente
- accesso controllato ai report cifrati
- tracciamento degli accessi ai dati clinici

---

### 📌 4. Verifica automatica delle firme digitali
Lo smart contract conserva la chiave pubblica del dispositivo IoT e:
1. verifica la firma digitale del report
2. controlla la corrispondenza della chiave pubblica
3. verifica il timestamp
4. registra il report solo se valido

