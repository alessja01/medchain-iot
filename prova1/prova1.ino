
#include "secret.h"
#include "device_key.h"

#include <Arduino.h>
#include <WiFiS3.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <EEPROM.h>

// Sensori e Display
#include <MAX30105.h>
#include <heartRate.h>
#include <Protocentral_MAX30205.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <malloc.h>

// Crypto
#include <Crypto.h>
#include <Ed25519.h>

// ====== CONFIGURAZIONE ======
const char* ssid     = WIFI_SSID;
const char* password = WIFI_PASSWORD;
const char* mqtt_server = MQTT_SERVER;
const int mqtt_port  = MQTT_PORT; // Porta TLS

const char* deviceId = DEVICE_ID;

const char* mqtt_topic_data   = "medchain/patient1";
const char* mqtt_topic_reg    = "medchain/register";
const char* mqtt_topic_proof  = "medchain/register/proof";
const char* mqtt_topic_status = "medchain/status/patient1";

String challengeTopic;
String ackTopic;

// ===== EEPROM LAYOUT =====
const uint32_t EEPROM_MAGIC_VALUE = 0x4D43484E; // "MCHN"
const int EEPROM_ADDR_MAGIC   = 0;             // 4 bytes (indirizzo partenza)
const int EEPROM_ADDR_COUNTER = 4;             // 4 bytes (counter anti-replay non riparti da 1 dal counter precedente +1)
const int EEPROM_ADDR_PRIVKEY = 8;             // 32 bytes (indirizzo chiave privata)

// ====== CHIAVI ED25519 ======
static uint8_t DEVICE_PRIVKEY[32];   // ora viene caricata/generata
static uint8_t DEVICE_PUBKEY[32];    //derivata 


// ====== STATO E SENSORI ======
WiFiSSLClient net;
PubSubClient client(net);
Adafruit_SSD1306 display(128, 64, &Wire, -1);
MAX30205 tempSensor;
MAX30105 pulseSensor;

bool provisioned = false;
uint32_t counter = 0;
unsigned long lastPublish = 0;
int beatAvg = 0;
long lastBeat = 0;

//Anti-replay ACK base
String lastChallengeNonce="";
bool waitingAck=false;

//  ====== COUNTER ======
void loadCounter() {
  EEPROM.get(EEPROM_ADDR_COUNTER, counter);
  if (counter == 0xFFFFFFFF) counter = 0;
  Serial.print("[CTR] counter iniziale=");
  Serial.println(counter);
}

void saveCounter() {
  EEPROM.put(EEPROM_ADDR_COUNTER, counter);
}

//====== RNG ======
void seedRng() {
  randomSeed((unsigned long)micros() ^ (unsigned long)millis());
}

void fillRandom(uint8_t* out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    out[i] = (uint8_t)random(0, 256);
  }
}


// ====== KEY per device in EEPROM ======
void loadOrCreateDeviceKey() {
  uint32_t magic = 0;
  EEPROM.get(EEPROM_ADDR_MAGIC, magic);

  if (magic == EEPROM_MAGIC_VALUE) {
    for (int i = 0; i < 32; i++) {
      DEVICE_PRIVKEY[i] = EEPROM.read(EEPROM_ADDR_PRIVKEY + i);
    }
    Serial.println("[KEY] PrivKey caricata da EEPROM ");
  } else {
    seedRng();
    fillRandom(DEVICE_PRIVKEY, 32);

    EEPROM.put(EEPROM_ADDR_MAGIC, EEPROM_MAGIC_VALUE);
    for (int i = 0; i < 32; i++) {
      EEPROM.write(EEPROM_ADDR_PRIVKEY + i, DEVICE_PRIVKEY[i]);
    }
    Serial.println("[KEY] PrivKey generata e salvata in EEPROM ");
  }

  Ed25519::derivePublicKey(DEVICE_PUBKEY, DEVICE_PRIVKEY);
}

// ====== UTILS HEX & CRYPTO ======

String toHex(const uint8_t* data, size_t len) {
  const char hexmap[] = "0123456789abcdef";
  String s = "";
  for (size_t i = 0; i < len; i++) {
    s += hexmap[(data[i] >> 4) & 0x0F];
    s += hexmap[data[i] & 0x0F];
  }
  return s;
}

bool fromHex(const String& hex, uint8_t* out, size_t outLen) {
  if (hex.length() < (int)(outLen * 2)) return false;
  for (size_t i = 0; i < outLen; i++) {
    char c1 = hex[i*2], c2 = hex[i*2+1];
    auto hv = [](char c) {
      return (c>='0'&&c<='9') ? (c-'0') :
             (c>='a'&&c<='f') ? (c-'a'+10) :
             (c>='A'&&c<='F') ? (c-'A'+10) : 0;
    };
    out[i] = (hv(c1) << 4) | hv(c2);
  }
  return true;
}

bool isHexLen(const String& s, size_t len) {
  if (s.length() != (int)len) return false;
  for (size_t i = 0; i < len; i++) {
    char c = s[i];
    bool ok = (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
    if (!ok) return false;
  }
  return true;
}


String signHex(const String& canonical) {
  uint8_t sig[64];
  Ed25519::sign(sig, DEVICE_PRIVKEY, DEVICE_PUBKEY, (const uint8_t*)canonical.c_str(), canonical.length());
  return toHex(sig, 64);
}

bool verifyHex(const String& pubKeyHex, const String& canonical, const String& sigHex) {
  if (!isHexLen(pubKeyHex, 64) || !isHexLen(sigHex, 128)) return false;
  uint8_t pub[32], sig[64];
  if (!fromHex(pubKeyHex, pub, 32)) return false;
  if (!fromHex(sigHex, sig, 64)) return false;
  return Ed25519::verify(sig, pub,
                         (const uint8_t*)canonical.c_str(), canonical.length());
}
// ==== STRICT TIME =====
bool timeReady() {
  unsigned long t = WiFi.getTime();
  return t > 1700000000UL;
}

unsigned long getEpochStrict() {
  return WiFi.getTime();
}

// ====== FUNZIONI DI INVIO ======
void sendRegister() {
  if(!timeReady()){
    Serial.println("[TIME] Ora non valida: REGISTER non inviato");
    return;
  }

  unsigned long ts = getEpochStrict();
  counter++;
  saveCounter();

  String pk = toHex(DEVICE_PUBKEY, 32);
  String canon = "REGISTER|" + String(deviceId) + "|" + String(ts) + "|" + String(counter) + "|" + pk;
  
  StaticJsonDocument<512> doc;
  doc["type"] = "REGISTER";
  doc["deviceId"] = deviceId;
  doc["timestamp"] = ts;
  doc["counter"] = counter;
  doc["pubKey"] = pk;
  doc["sig"] = signHex(canon);

  char buffer[512];
  serializeJson(doc, buffer);
  client.publish(mqtt_topic_reg, buffer);
  Serial.println("[MQTT] REGISTER Inviato");
}

void sendProof(const String& nonce) {

  if(!timeReady()){
    Serial.println("[TIME] Ora non valida: PROOF non inviato");
    return;
  }

  if(!isHexLen(nonce,32)){
    Serial.println("[MQTT]: PROOF nonce invalido");
    return;
  }

  unsigned long ts=getEpochStrict();
  counter++;
  saveCounter();

  String canon = "PROOF|" + String(deviceId) + "|" + nonce + "|" + String(ts) + "|" + String(counter);
  
  StaticJsonDocument<512> doc;
  doc["type"] = "PROOF";
  doc["deviceId"] = deviceId;
  doc["nonce"] = nonce;
  doc["timestamp"] = ts;
  doc["counter"] = counter;
  doc["sig"] = signHex(canon);

  char buffer[512];
  serializeJson(doc, buffer);
  client.publish(mqtt_topic_proof, buffer);
  Serial.println("[MQTT] PROOF Inviato");
}

// ====== CALLBACK MQTT ======
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  StaticJsonDocument<512> doc;
  DeserializationError err = deserializeJson(doc, payload, length);
  if (err) {
    Serial.print("[MQTT] JSON err: ");
    Serial.println(err.c_str());
    return;
  }

  String type=doc["type"] | "";

  if (type == "CHALLENGE") {
    String nonce = doc["nonce"] | "";
    if(!isHexLen(nonce,32)){
      Serial.println("[MQTT] CHALLENGE nonce invalido -> scarto");
      return;
    }

    Serial.println("[MQTT] Ricevuta CHALLENGE");
    lastChallengeNonce=nonce;
    waitingAck=true;
    sendProof(nonce);

  } 
  else if (type == "ACK") {
    String status = doc["status"] | "";
    String sig = doc["sig"] | "";
    String nonce = doc["nonce"] | "";
    unsigned long ts = doc["timestamp"] | 0UL;

    if (!waitingAck) {
      Serial.println("[MQTT] ACK inatteso -> scarto");
      return;
    }
    if (!isHexLen(sig, 128) || !isHexLen(nonce, 32) || ts == 0) {
      Serial.println("[MQTT] ACK campi invalidi -> scarto");
      return;
    }
    if (nonce != lastChallengeNonce) {
      Serial.println("[MQTT] ACK nonce mismatch (replay?) -> scarto");
      return;
    }
    
    String canon = "ACK|" + String(deviceId) + "|" + String(ts) + "|" + status + "|" + nonce;
    if (verifyHex(GATEWAY_PUBKEY_HEX, canon, sig) && status == "OK") {
      provisioned = true;
      Serial.println("[MQTT] Provisioning COMPLETATO ");
    }
  }
}

// ====== CONNECT MQTT ======
void connectMQTT() {
  while (!client.connected()) {
    Serial.println("\n--- DIAGNOSTICA CONNESSIONE ---");
    
    
    // 2. Test Handshake SSL
    if (net.connect(mqtt_server, mqtt_port)) {
      Serial.println("Handshake SSL riuscito! ");
      net.stop(); 
      
      // 3. Generiamo un ID più corto e semplice (max 23 caratteri)
      String shortId = "R4ALE" + String(millis()).substring(0, 5);
      
      Serial.print("Tentativo MQTT con ID: ");
      Serial.println(shortId);

      // 4. Connessione SEMPLIFICATA
      if (client.connect(shortId.c_str())) { 
        Serial.println("CONNESSO FINALMENTE!");
        
        client.subscribe(challengeTopic.c_str());
        client.subscribe(ackTopic.c_str());
        
        // Invio immediato del registro
        sendRegister();
      } else {
        Serial.print("ERRORE MQTT: rc=");
        Serial.println(client.state());
        // Se continua a dare -2, il broker potrebbe richiedere username/password sulla 8883
      }
    } else {
      Serial.println("ERRORE SSL: Handshake fallito.");
    }

    Serial.println("-------------------------------\n");
    delay(5000);
  }
}

void setup() {
  Serial.begin(115200);
  Wire.begin();
  
  // 1. Inizializza sensori e display
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();
  display.display();
  
  tempSensor.begin();
  pulseSensor.begin();
  pulseSensor.setup();

  // 2. Connetti WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi OK.");

  // 3. ASPETTA SINCRONIZZAZIONE ORA (Vitale per TLS e anti replay)
  Serial.print("Sincronizzazione ora NTP...");
  unsigned long startWait = millis();
  while (WiFi.getTime() == 0 && millis() - startWait < 15000) {
    delay(500);
    Serial.print(".");
  }
  Serial.println(WiFi.getTime() != 0 ? " Sincronizzato! " : " Fallito (uso fallback) ");

  // 4. Carica counter e chiave device
  loadCounter();
  loadOrCreateDeviceKey();

  //5. Topic dipendenti dal deviceId
  challengeTopic=String("medchain/challenge/")+ deviceId;
  ackTopic= String("medchain/register/ack/")+ deviceId;

  //6. Configura MQTT
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(onMqttMessage);
  client.setBufferSize(1024);
  client.setKeepAlive(60);
  
  connectMQTT();
}

void loop() {
  if (!client.connected()) connectMQTT();
  client.loop();

  if (!provisioned) {
    display.clearDisplay();
    display.setCursor(0,0);
    display.setTextColor(WHITE);
    display.println("STATO: REGISTRAZIONE");
    display.println("In attesa di ACK...");
    display.display();
    
    static unsigned long lastReg = 0;
    if (millis() - lastReg > 10000) { lastReg = millis(); sendRegister(); }
    return;
  }

  // Lettura Sensori
  long irValue = pulseSensor.getIR();
  if (checkForBeat(irValue)) {
    long delta = millis() - lastBeat;
    lastBeat = millis();
    float bpm = 60 / (delta / 1000.0);
    if (bpm < 255 && bpm > 20) beatAvg = (int)bpm;
  }

  if (millis() - lastPublish > 5000) {
    lastPublish = millis();

    if(!timeReady()){
      Serial.println("[TIME] Ora non valide: VITALS skip");
      return;
    }


    float temp = tempSensor.getTemperature();
    int hr = (irValue > 50000) ? beatAvg : 0;
    int spo2 = (hr > 0) ? 98 : 0;
    int tempCenti = (int)(temp * 100);
    unsigned long ts = getEpochStrict();
  
    counter ++;
    saveCounter();

    String canon = "VITALS|" + String(deviceId) + "|" + String(ts) + "|" + String(counter) + "|" + String(hr) + "|" + String(spo2) + "|" + String(tempCenti);
    
    StaticJsonDocument<768> doc;
    doc["type"] = "VITALS";
    doc["deviceId"] = deviceId;
    doc["timestamp"] = ts;
    doc["counter"] = counter;
    doc["heartRate"] = hr;
    doc["spo2"] = spo2;
    doc["temperature"] = tempCenti;
    doc["sig"] = signHex(canon);

    char buffer[1024];
    serializeJson(doc, buffer);
    client.publish(mqtt_topic_data, buffer);

    display.clearDisplay();
    display.setCursor(0,0);
    display.println("MEDCHAIN MONITOR");
    display.print("BPM: "); display.println(hr);
    display.print("TEMP: "); display.println(temp);
    display.display();
  }
}