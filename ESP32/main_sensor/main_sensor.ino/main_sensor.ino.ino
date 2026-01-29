#include <WiFi.h>                      //LIBRERIA WIFI 
#include <PubSubClient.h>             //LIBRERIA CLIENT MQTT
#include <ArduinoJson.h>             //LIBRERIA JSON
#include "Protocentral_MAX30205.h"  //MAX30205
#include <Wire.h>                  //LIBRERIA PER BUS 12C
#include "mbedtls/md.h"           // per HMAC-SHA256
#include "time.h"                //LIBRERIA GESTIONE DATA/ORA

// ====== CONFIG WIFI ======
const char* ssid     = "Vodafone5GHz-Wifi6";
const char* password = "Suanalar@1977!Suanalar@1977!";

// ====== CONFIG MQTT ======
const char* mqtt_server = "broker.hivemq.com"; //indirizzo del broker MQTT pubblico
const int   mqtt_port   = 1883; // Porta standard MQTT non cifrata
const char* mqtt_topic  = "medchain/patient1";  //Topic su cui l'ESP32 pubblica i dati

// ====== CONFIG SENSORI ======
MAX30205 tempSensor;   

// ====== DEVICE INFO ======
const char* deviceId = "esp32-001"; //Identificativo univoco del dispositivo IOT

// Chiave segreta HMAC condivisa con il gateway
const char* HMAC_KEY = "supersecretHMACkey42";


// ====== MQTT / WIFI ======
WiFiClient espClient; //Oggetto client TCP di base per WIFi
PubSubClient client(espClient); //Client MQTT che usa il WiFICLient

// ====== CONFIG NTP ======
const char* ntpServer          = "pool.ntp.org"; //Server NTP per sincronizzare l'ora
const long  gmtOffset_sec      = 3600;           //Offset fuso orario 
const int   daylightOffset_sec = 3600;          //Ora legare

// ------------------------
// FUNZIONI WIFI / MQTT
// ------------------------

void setup_wifi() {
  Serial.println();
  Serial.print("Connessione a ");
  Serial.println(ssid);

  //Avvia la connessione WiFi
  WiFi.begin(ssid, password);

  //Attende finchè l'ESP32 non è connesso alla rete
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  //Una volta connesso:
  Serial.println("\nWiFi connesso");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP()); //stampa l'IP assegnato dall' AP
}

void reconnect_mqtt() {
  //Finchè il client MQTT non è connesso, prova a riconnettersi
  while (!client.connected()) {
    Serial.print("Connessione broker MQTT...");
    //prova a connettersi usando l'ID ESP32_MedChain_Client
    if (client.connect("ESP32_MedChain_Client")) {
      Serial.println(" OK"); //connessione riuscita
    } else {
      Serial.print(" fallita, rc="); //connessione fallita
      Serial.print(client.state()); //Codice errore MQTT
      Serial.println(" ritento tra 5 secondi");
      delay(5000); //Attendi 5 sec
    }
  }
}

void setup_time() {
  //Configura il sistema per usare NTP
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
  Serial.println("Sincronizzazione NTP...");

  struct tm timeinfo;

  //Prova a leggere l'ora corrente dal sistema (sincronizzata con NTP)
  if (!getLocalTime(&timeinfo)) {
    Serial.println("Errore NTP"); //Se fallisce, niente timestamp "reale"
  } else {
    Serial.println("Ora sincronizzata");
  }
}

//Ritorna il timestamp corrente in secondi
unsigned long getEpochTime() {
  time_t now;
  time(&now); //lege il tempo corrente dal sistema
  return (unsigned long)now; //lo converte in unsigned long
}

// ------------------------
// LETTURA SENSORI
// ------------------------

//Legge la temperatura
float readTemperature() {
  float t = tempSensor.getTemperature(); //Chiamata alla libreria ProtoCentral

  //controllo che la temperatura sia valida
  if (isnan(t)) {
    Serial.println("Errore lettura MAX30205");
    return -1000.0; //valore di errore
  }
  return t; //temperatura valida in C
}

//valori finti per battito cardiaco e Sp02
int readHeartRate() { return 75; }
int readSpO2()      { return 98; }

//Calcola HMAC-SHA256 usando HMAC_KEY e restituisce stringa esadecimale
String computeHmacSha256(const String& message) {
  //ottiene le info sull'algoritmo SHA256 per mbedTLS
  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  //Buffer per i 32 byte di output
  unsigned char hmac[32];


  mbedtls_md_context_t ctx; //contesto mbedTLS
  mbedtls_md_init(&ctx); //Inizializza il contesto

  //configura il contesto per usare SHA256 in modalità HMAC
  if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
    Serial.println("Errore mbedtls_md_setup");
    mbedtls_md_free(&ctx); //Libreria risorse
    return "";
  }

  //Avvia l'HMAC con la chiave Segreta HMAC_KEY
  if (mbedtls_md_hmac_starts(&ctx, (const unsigned char*)HMAC_KEY, strlen(HMAC_KEY)) != 0) {
    Serial.println("Errore hmac_starts");
    mbedtls_md_free(&ctx);
    return "";
  }

  //Aggiunge il messaggio da firmare all'HMAC
  if (mbedtls_md_hmac_update(&ctx, (const unsigned char*)message.c_str(), message.length()) != 0) {
    Serial.println("Errore hmac_update");
    mbedtls_md_free(&ctx);
    return "";
  }

  //Completa il calcolo dell'HMAC e scrive il risultato in 'hmac'
  if (mbedtls_md_hmac_finish(&ctx, hmac) != 0) {
    Serial.println("Errore hmac_finish");
    mbedtls_md_free(&ctx);
    return "";
  }

  //libreria il contesto
  mbedtls_md_free(&ctx);

  // Convertiamo i 32 byte in stringa esadecimale (64 caratteri)
  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hex + (i * 2), "%02x", hmac[i]); //ogni byte --> 2 char esadecimali 
  }
  hex[64] = '\0'; //Terminatore di stringa c

  return String(hex); //restituisce HMAC come String Arduino
}



// ------------------------
// COSTRUISCI E INVIA JSON
// ------------------------

void publishVitals() {

  //LETTURA SENSORI
  float temperature = readTemperature(); //Legge la temperatura corporea
  if (temperature == -1000.0) { //se la lettura è invalida esci
    return;
  }

  int heartRate= readHeartRate();
  int spo2= readSp02();
  unsigned long timestamp= getEpochTime();

  //COSTRUISCO LA STRINGA CANONICA
  //  deviceID|timestamp|heartRate|spo2|temperatore_con_2_decimali
  int tempCenti= (int)lround(temperature*100.0); //temperatura in centigradi (2 decimali)
  String toSign=  String(deviceId)+"|"+
                  String(timestamp)+"|"+
                  String(heartRate)+"|"+
                  String(spo2)+"|"+
                  String(tempCenti);
  
  //CALCOLO HMAC-SHA256 della stringa
  String hmac= computeHmacSha256(toSign);

  Serial.println("[HMAC] Stringa firmata (ESP32):");
  Serial.println(toSign);
  Serial.print("[HMAC] valore HMAC:");
  Serial.println(hmac);

  //crea un documento JSON con buffer statico di 256 byte
  StaticJsonDocument<256> doc;
  doc["deviceId"]   = deviceId;       //ID del documento
  doc["timestamp"]  = getEpochTime(); //Timestamp corrente
  doc["heartRate"]  = readHeartRate();//Battito 
  doc["spo2"]       = readSpO2();     //Sp02
  doc["temperature"]= tempCenti;    //Temperatura misurata
  doc["hmac"]       =hmac;//firma di autencità del messaggio 

  String payload;
  serializeJson(doc, payload);//serializza il json in una strinfa

  Serial.println("[ESP32] JSON inviato:");
  Serial.println(payload); //stampa il Json sul serial monitor

  client.publish(mqtt_topic, payload.c_str());
}

// ------------------------
// SETUP & LOOP
// ------------------------

unsigned long lastPublish = 0; //ultimo momento in cui abbiamo inviato i dati
const unsigned long publishInterval = 5000; //Intervallo tra invii (ms)--> 5s

void setup() {
  Serial.begin(115200); //Inizializza la seriale per debug
  Serial.println("Avvio ESP32 - MAX30205");

  Wire.begin(); //Avvia il bus I2C
  tempSensor.begin();  // INIZIALIZZA IL SENSORE CORRETTAMENTE

  setup_wifi(); //Connessione al WiFi
  setup_time(); //Sincronizzazione ora via NTP
  client.setServer(mqtt_server, mqtt_port); //Configura l'indirizzo del broker MQTT
}

void loop() {
  //Se il client MQTT non è connesso, prova a riconnettersi
  if (!client.connected()) reconnect_mqtt();
  client.loop(); //Gestisce la comunicazione MQTT in background

  if (millis() - lastPublish > publishInterval) {
    lastPublish = millis();
    publishVitals();
  }
}
