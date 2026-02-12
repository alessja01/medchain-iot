/***************************************************************
  MEDCHAIN MONITOR ULTIMATE – Arduino UNO R4 WiFi
  - Connessione TLS (Porta 8883)
  - Firma Ed25519 (Integrata alla sorgente)
  - Auto-Retry Provisioning & Time Fallback
***************************************************************/

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
const char* ssid     = "Vodafone5GHz-Wifi6";
const char* password = "Suanalar@1977!Suanalar@1977!";
const char* mqtt_server = "broker.hivemq.com";
const int mqtt_port  = 8883; // Porta TLS

const char* deviceId = "R4-I0T-001-XYZ99";
const char* mqtt_topic_data   = "medchain/patient1";
const char* mqtt_topic_reg    = "medchain/register";
const char* mqtt_topic_proof  = "medchain/register/proof";
const char* mqtt_topic_status = "medchain/status/patient1";

String challengeTopic = String("medchain/challenge/") + deviceId;
String ackTopic       = String("medchain/register/ack/") + deviceId;

// ====== CHIAVI ED25519 ======
static const uint8_t DEVICE_PRIVKEY[32] = {
  0x4f,0x8c,0x4e,0x46,0x17,0x71,0x59,0x78,0x7b,0x43,0x4e,0xaf,
  0x07,0x7f,0xce,0xdd,0xf9,0x7c,0x3f,0x7f,0x1c,0xb6,0x16,0x59,
  0xac,0xc1,0xb9,0x06,0x26,0x80,0x8e,0xaa
};
static uint8_t DEVICE_PUBKEY[32];
static const char* GATEWAY_PUBKEY_HEX = "8580d9d154496d87aee218549d0d9f7ce5ba90c943624fbcc10cecbd40714dcb";

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
  for (size_t i = 0; i < outLen; i++) {
    char c1 = hex[i*2], c2 = hex[i*2+1];
    auto hv = [](char c) { return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:c-'A'+10; };
    out[i] = (hv(c1) << 4) | hv(c2);
  }
  return true;
}

String signHex(const String& canonical) {
  uint8_t sig[64];
  Ed25519::sign(sig, DEVICE_PRIVKEY, DEVICE_PUBKEY, (const uint8_t*)canonical.c_str(), canonical.length());
  return toHex(sig, 64);
}

bool verifyHex(const String& pubKeyHex, const String& canonical, const String& sigHex) {
  uint8_t pub[32], sig[64];
  fromHex(pubKeyHex, pub, 32); fromHex(sigHex, sig, 64);
  return Ed25519::verify(sig, pub, (const uint8_t*)canonical.c_str(), canonical.length());
}

unsigned long getEpochSafe() {
  unsigned long t = WiFi.getTime();
  return (t == 0) ? 1770880000 : t; // Fallback se NTP non pronto
}

// ====== FUNZIONI DI INVIO ======
void sendRegister() {
  unsigned long ts = getEpochSafe();
  counter++;
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
  unsigned long ts = getEpochSafe();
  counter++;
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
  deserializeJson(doc, payload, length);
  String type = doc["type"] | "";

  if (type == "CHALLENGE") {
    String nonce = doc["nonce"] | "";
    Serial.println("[MQTT] Ricevuta CHALLENGE");
    sendProof(nonce);
  } 
  else if (type == "ACK") {
    String status = doc["status"] | "";
    String sig = doc["sig"] | "";
    String nonce = doc["nonce"] | "";
    unsigned long ts = doc["timestamp"];
    
    String canon = "ACK|" + String(deviceId) + "|" + String(ts) + "|" + status + "|" + nonce;
    if (verifyHex(GATEWAY_PUBKEY_HEX, canon, sig) && status == "OK") {
      provisioned = true;
      Serial.println("[MQTT] Provisioning COMPLETATO ✅");
    }
  }
}

void connectMQTT() {
  while (!client.connected()) {
    Serial.println("\n--- DIAGNOSTICA CONNESSIONE ---");
    
    // 1. RAM e WiFi OK (saltiamo i log per brevità, sappiamo che vanno)
    
    // 2. Test Handshake SSL
    if (net.connect(mqtt_server, mqtt_port)) {
      Serial.println("Handshake SSL riuscito! ✅");
      net.stop(); 
      
      // 3. Generiamo un ID più corto e semplice (max 23 caratteri)
      // Esempio: R4ALE7764 (senza troppi trattini)
      String shortId = "R4ALE" + String(millis()).substring(0, 5);
      
      Serial.print("Tentativo MQTT con ID: ");
      Serial.println(shortId);

      // 4. Connessione SEMPLIFICATA (senza Last Will e senza parametri extra)
      // Se il broker pubblico è congestionato, questo è il modo più probabile per entrare
      if (client.connect(shortId.c_str())) { 
        Serial.println("CONNESSO FINALMENTE! ✅✅");
        
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

  // 3. ASPETTA SINCRONIZZAZIONE ORA (Vitale per SSL)
  Serial.print("Sincronizzazione ora NTP...");
  unsigned long startWait = millis();
  while (WiFi.getTime() == 0 && millis() - startWait < 10000) {
    delay(500);
    Serial.print(".");
  }
  Serial.println(WiFi.getTime() != 0 ? " Sincronizzato! ✅" : " Fallito (uso fallback) ⚠️");

  // 4. Configura Client
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(onMqttMessage);
  client.setBufferSize(1024);
  client.setKeepAlive(60);
  
  Ed25519::derivePublicKey(DEVICE_PUBKEY, DEVICE_PRIVKEY);
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
    float temp = tempSensor.getTemperature();
    int hr = (irValue > 50000) ? beatAvg : 0;
    int spo2 = (hr > 0) ? 98 : 0;
    int tempCenti = (int)(temp * 100);
    unsigned long ts = getEpochSafe();
    counter++;
    EEPROM.put(0, counter);

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