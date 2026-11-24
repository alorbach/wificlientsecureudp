/*
  DtlsPskClient - WiFiClientSecureUdp example

  Connects to a DTLS server using a pre-shared key (PSK), sends a
  datagram and prints the reply.

  You can test it with an OpenSSL DTLS server on your PC, e.g.:
    openssl s_server -dtls -accept 4433 -nocert \
      -psk 0102030405060708090a0b0c0d0e0f10 -psk_identity esp32-client

  Requirements: ESP32 board, mbedTLS built with MBEDTLS_SSL_PROTO_DTLS
  (enabled in the default ESP32 Arduino core).
*/

#include <WiFi.h>
#include <WiFiClientSecureUdp.h>

const char *ssid     = "your_SSID";
const char *password = "your_PASSWORD";

const char *host = "192.168.1.100";   // DTLS server
const uint16_t port = 4433;

// PSK identity and key (key as hex string, max 32 bytes)
const char *pskIdent = "esp32-client";
const char *psKey    = "0102030405060708090a0b0c0d0e0f10";

WiFiClientSecureUdp client;

void setup() {
  Serial.begin(115200);
  delay(100);

  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("WiFi connected, IP: ");
  Serial.println(WiFi.localIP());

  client.setPreSharedKey(pskIdent, psKey);
  client.setHandshakeTimeout(10);  // seconds

  Serial.printf("Connecting to %s:%u via DTLS...\n", host, port);
  if (!client.connect(host, port)) {
    char err[100];
    client.lastError(err, sizeof(err));
    Serial.printf("Connection failed: %s\n", err);
    return;
  }
  Serial.println("DTLS session established");
}

void loop() {
  if (!client.connected()) {
    delay(1000);
    return;
  }

  client.print("Hello from ESP32 over DTLS");

  unsigned long start = millis();
  while (!client.available() && millis() - start < 2000) {
    delay(10);
  }
  while (client.available()) {
    Serial.write(client.read());
  }
  Serial.println();

  delay(5000);
}
