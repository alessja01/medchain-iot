#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "DHT.h"

//CONIG WIFI
const char* ssid="Vodafone5GHz-Wifi6";
const char* password= "Suanalar@1977!Suanalar@1977!";

//CONFIG MQTT
const char* mqtt_server = "broker.hivemq.com"; //indirizzo del broker MQTT
const int   mqtt_port   = 1883; //porta TCP
const char* mqtt_topic  = "medchain/patient1"; //il canale dove esp32 publica i datu


//CONFIG DHT11
#define DHTPIN 4
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);


//Device info
const char* deviceId = "esp32-001";// una stringa che identifica il tuo device così capisco quale dispositivo 

//Oggetti wifi + mqtt
WiFiClient espClient; //oggetto base per fare connessioni TCP via WIFi
PubSubClient client(espClient); //client MQTT userà WiFiClient per parlare con il broker


//Connessione Wifi 
void setup_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Connessione a ");
  Serial.println(ssid);

  WiFi.begin(ssid, password); //fa collegare l'ESP32 al Wifi

  while (WiFi.status() != WL_CONNECTED) { //ciclo che aspetta finchè non è connesso 
    delay(500);
    Serial.print(".");
  }//ogni 500ms stampa un punto per capire che ci sta a provà

  Serial.println("");
  Serial.println("WiFi connesso");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP()); //stampa wifi e l'ip
}


//Riconnessione MQTT
void reconnect_mqtt() {
  while (!client.connected()) { // finchè client non è connesso riprova
    Serial.print("Connessione al broker MQTT...");
    if (client.connect("ESP32_MedChain_Client")) { // prova a connettere l'Esp32 al broker HiveMQ
      Serial.println(" connesso");
    } else {
      Serial.print(" fallita, rc=");
      Serial.print(client.state()); // stampa il codice di errore dalla libreria
      Serial.println(" ritento tra 5 secondi");
      delay(5000);
    }
  }
}


//set up solo una volta parte
void setup() {
  Serial.begin(115200); // per il debug sul Serial Monitor
  Serial.println("DHT11 + MQTT test"); 

  dht.begin(); // inzializza il sensore DHT11
  setup_wifi(); // connessione al Wifi

  client.setServer(mqtt_server, mqtt_port); //client MQTT a quale broker si deve connettere
}


//loop
void loop() {
  if (!client.connected()) {
    reconnect_mqtt(); // se non sei connesso al broker 
  }
  client.loop(); // fa funzionare la liberia MQTT

  // Leggi DHT11
  float temp = dht.readTemperature();
  float hum  = dht.readHumidity();

  if (isnan(temp) || isnan(hum)) { // controlla se sono validi 
    Serial.println("Errore lettura DHT11, non invio nulla.");
    delay(2000);
    return;
  }

  // Costruisci JSON
  StaticJsonDocument<256> doc; // buffer per costruire il JSON
  doc["deviceId"]  = deviceId;
  doc["timestamp"] = millis() / 1000;  //secondi di accesione

  JsonObject data = doc.createNestedObject("data"); // oggetto interno data con temperatura e umidità 
  data["temperature"] = temp;
  data["humidity"]    = hum;

  // Serializza JSON in stringa
  String payload;
  serializeJson(doc, payload); // trasforma l'oggetto JSON in stringa

  // Stampa su Serial
  Serial.println("[ESP32] Invia su MQTT:");
  Serial.println(payload);

  // Invia su MQTT
  client.publish(mqtt_topic, payload.c_str()); // manda la stringa al broker MQTT sul topic 

  delay(3000); // ogni 3 secondi
}
