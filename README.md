# WiFiClientSecureUdp

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/alorbach/wificlientsecureudp)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-green.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-ESP32-orange.svg)](https://www.espressif.com/en/products/socs/esp32)

A secure UDP client library for ESP32 that implements DTLS (Datagram Transport Layer Security) using mbedTLS. This library provides encrypted and authenticated UDP communication, making it ideal for IoT applications requiring secure datagram transport.

## Features

- **DTLS Support**: Secure UDP connections using Datagram Transport Layer Security
- **Multiple Authentication Methods**:
  - Root CA certificate authentication
  - Client certificate and private key authentication
  - Pre-shared key (PSK) authentication
- **ESP32 Compatibility**: Supports both ESP32 Arduino 2.x and 3.x
- **Error Handling**: Enhanced error reporting with errno information and LwIP statistics
- **Memory Management**: Automatic retry logic for memory-related errors
- **WiFiClient Interface**: Inherits from WiFiClient, providing familiar API

## Requirements

- **Hardware**: ESP32 development board
- **Arduino IDE**: Version 1.8.13 or later (or PlatformIO)
- **ESP32 Arduino Core**: Version 1.0.4 or later (2.x and 3.x supported)
- **mbedTLS**: Must be compiled with `MBEDTLS_SSL_PROTO_DTLS` enabled

## Installation

### Arduino IDE

1. Download this repository as a ZIP file
2. In Arduino IDE, go to `Sketch` → `Include Library` → `Add .ZIP Library...`
3. Select the downloaded ZIP file
4. The library will be installed in your Arduino libraries folder

### PlatformIO

Add to your `platformio.ini`:

```ini
lib_deps = 
    https://github.com/alorbach/wificlientsecureudp.git
```

### ESP32 SDK Configuration

**Important**: The mbedTLS library must be compiled with DTLS support enabled.

#### For ESP32 Arduino 2.x and 3.x:

The ESP32 Arduino framework should already have DTLS support. If not, you may need to:

1. Edit your `sdkconfig` file (usually in `~/.platformio/packages/framework-arduinoespressif32/tools/sdk/sdkconfig` or similar)
2. Ensure the following is set:
   ```
   CONFIG_MBEDTLS_SSL_PROTO_DTLS=y
   ```

#### Manual mbedTLS Compilation (Advanced)

If you need to compile mbedTLS yourself, follow the [ESP-IDF Component documentation](https://github.com/espressif/arduino-esp32/blob/master/docs/esp-idf_component.md).

After compilation, replace these files in your ESP32 Arduino framework:
- `packages/esp32/hardware/esp32/[version]/tools/sdk/sdkconfig`
- `packages/esp32/hardware/esp32/[version]/tools/sdk/include/config/sdkconfig.h`
- `packages/esp32/hardware/esp32/[version]/tools/sdk/lib/libmbedtls.a`
- `packages/esp32/hardware/esp32/[version]/tools/sdk/include/mbedtls/mbedtls/*`

## Quick Start

### Basic Example

```cpp
#include <WiFi.h>
#include <WiFiClientSecureUdp.h>

const char* ssid = "your_SSID";
const char* password = "your_PASSWORD";
const char* host = "example.com";
const uint16_t port = 4433;

// Root CA certificate (for server authentication)
const char* rootCACertificate = \
"-----BEGIN CERTIFICATE-----\n" \
"...\n" \
"-----END CERTIFICATE-----\n";

WiFiClientSecureUdp client;

void setup() {
    Serial.begin(115200);
    
    // Connect to WiFi
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("WiFi connected");
    
    // Set CA certificate
    client.setCACert(rootCACertificate);
    
    // Connect to server
    if (client.connect(host, port)) {
        Serial.println("Connected to server");
        
        // Send data
        client.println("Hello, DTLS Server!");
        
        // Read response
        while (client.available()) {
            char c = client.read();
            Serial.print(c);
        }
    } else {
        Serial.println("Connection failed");
    }
}

void loop() {
    // Your code here
}
```

## API Reference

### Connection Methods

#### Basic Connection
```cpp
int connect(IPAddress ip, uint16_t port);
int connect(IPAddress ip, uint16_t port, int32_t timeout);
int connect(const char *host, uint16_t port);
int connect(const char *host, uint16_t port, int32_t timeout);
```

#### Connection with Certificates
```cpp
int connect(IPAddress ip, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
int connect(const char *host, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
```

#### Connection with Pre-Shared Key
```cpp
int connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey);
int connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey);
```

### Certificate Management

```cpp
void setCACert(const char *rootCA);                    // Set root CA certificate
void setCertificate(const char *client_ca);            // Set client certificate
void setPrivateKey(const char *private_key);           // Set client private key
void setPreSharedKey(const char *pskIdent, const char *psKey);  // Set PSK (key in hex)

// Load certificates from Stream
bool loadCACert(Stream& stream, size_t size);
bool loadCertificate(Stream& stream, size_t size);
bool loadPrivateKey(Stream& stream, size_t size);
```

### Data I/O

```cpp
size_t write(uint8_t data);                           // Write single byte
size_t write(const uint8_t *buf, size_t size);        // Write buffer
int read();                                            // Read single byte
int read(uint8_t *buf, size_t size);                   // Read into buffer
int available();                                       // Check available bytes
int peek();                                            // Peek next byte
void flush();                                          // Flush output (no-op for UDP)
```

### Connection Management

```cpp
uint8_t connected();                                  // Check connection status
void stop();                                          // Close connection
void setHandshakeTimeout(unsigned long timeout);      // Set DTLS handshake timeout
```

### Error Handling

```cpp
int lastError(char *buf, const size_t size);          // Get last error message
void setwriteFailTimeout(int timeout);                // Set write failure timeout (ms)
void setwriteFailDelay(int delay);                     // Set write failure retry delay (ms)
```

### Certificate Verification

```cpp
bool verify(const char* fingerprint, const char* domain_name);  // Verify server certificate
```

## Authentication Methods

### 1. Root CA Certificate

Authenticates the server and negotiates an encrypted connection (similar to HTTPS in browsers).

**For your own server:**
1. Generate a root certificate for your CA
2. Generate a server certificate signed by your root CA
3. Use `setCACert()` with your root CA certificate

**For public servers:**
1. Obtain the public CA certificate that signed the server's certificate
2. Use `setCACert()` with the public CA certificate

### 2. Client Certificate Authentication

Adds client authentication to server authentication.

1. Generate a client certificate and private key using your root CA
2. Register the client certificate with your server
3. Use `setCACert()` for server authentication
4. Use `setCertificate()` and `setPrivateKey()` for client authentication

### 3. Pre-Shared Key (PSK)

Simpler authentication using a shared secret key.

1. Generate a random hex string (32 bytes max, commonly using MD5 or SHA)
2. Create a client ID string
3. Configure your server to accept the ID/key pair
4. Use `setPreSharedKey(pskIdent, psKey)` where `psKey` is in hex format

**Note**: PSK is more secure than plain passwords because the key is never directly transmitted, and the server is also authenticated to the client.

## ESP32 Version Compatibility

This library supports both ESP32 Arduino 2.x and 3.x:

- **ESP32 3.x**: Uses public mbedTLS timing API and updated header includes
- **ESP32 2.x**: Uses custom timing implementation and legacy headers

The library automatically detects the ESP32 version and uses the appropriate APIs.

## Error Handling

The library includes enhanced error handling:

- **Memory Errors**: On `ENOBUFS` errors, the library displays LwIP statistics and automatically retries after a delay
- **Write Failures**: Configurable timeout and retry delay for handling temporary write failures during UDP bursts
- **Error Logging**: All errors include errno information for better debugging

### Common Error Codes

- `MBEDTLS_ERR_NET_SEND_FAILED` (-0x004E): Network send failed (often temporary with UDP)
- `ENOBUFS`: Out of memory in TCP/IP stack (library will retry automatically)
- Connection timeouts: Adjust using `setHandshakeTimeout()`

## Troubleshooting

### Connection Fails

1. **Check DTLS support**: Ensure `CONFIG_MBEDTLS_SSL_PROTO_DTLS=y` in sdkconfig
2. **Verify certificates**: Ensure certificates are valid and properly formatted
3. **Check network**: Verify WiFi connection and server accessibility
4. **Review logs**: Enable debug logging to see detailed error messages

### Memory Errors

- The library automatically retries on memory errors
- If persistent, consider:
  - Reducing buffer sizes
  - Increasing FreeRTOS heap size
  - Reducing concurrent connections

### Write Failures

- UDP can experience temporary write failures during high burst traffic
- Use `setwriteFailTimeout()` and `setwriteFailDelay()` to handle transient errors
- Default behavior: connection closes immediately on write failure

## Limitations

- UDP is connectionless; the library maintains a pseudo-connection state
- No guarantee of packet delivery or ordering (UDP characteristics)
- Some TCP-specific socket options are not applicable (e.g., TCP_NODELAY, SO_KEEPALIVE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This library is licensed under the BSD 3-Clause License. See [LICENSE.txt](LICENSE.txt) for details.

## Credits

- **Original WiFiClientSecure**: Copyright (c) 2016 Hristo Gochkov, Additions Copyright (C) 2017 Evandro Luis Copercini
- **WiFiClientSecureUdp Fork**: Copyright (c) 2020 Andre Lorbach
- **mbedTLS**: Copyright (c) ARM Limited and Contributors

## Links

- [GitHub Repository](https://github.com/alorbach/wificlientsecureudp)
- [ESP32 Arduino Core](https://github.com/espressif/arduino-esp32)
- [mbedTLS Documentation](https://tls.mbed.org/)

## Support

For issues, questions, or contributions, please use the [GitHub Issues](https://github.com/alorbach/wificlientsecureudp/issues) page.
