/* Provide SSL/TLS functions to ESP32 with Arduino IDE
 * by Evandro Copercini - 2017 - Apache 2.0 License
 */

#ifndef ARD_SSL_UDP_H
#define ARD_SSL_UDP_H
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"

/*
#undef log_v(format, ...) 
*/
#undef log_d(format, ...) 
#undef log_i(format, ...) 
/**/
#undef log_w(format, ...) 
#undef log_e(format, ...) 

/*
#define log_v(format, ...) Serial.printf("ssl_client_udp verbose: " format "\n", ##__VA_ARGS__);
*/
#define log_d(format, ...) Serial.printf("ssl_client_udp debug: " format "\n", ##__VA_ARGS__);
#define log_i(format, ...) Serial.printf("ssl_client_udp info: " format "\n", ##__VA_ARGS__);
/**/
#define log_w(format, ...) Serial.printf("ssl_client_udp warning: " format "\n", ##__VA_ARGS__);
#define log_e(format, ...) Serial.printf("ssl_client_udp error: " format "\n", ##__VA_ARGS__);
// Uncomment for Ultraverbose debugging 
#define log_d_mbedtls(format, ...) Serial.printf("ssl_client_udp debug: " format, ##__VA_ARGS__);

typedef struct sslclientudp_context {
    int socket;
mbedtls_net_context socket_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;
	mbedtls_timing_delay_context timer;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
	/* Read , write Mutex */
	SemaphoreHandle_t mbedtls_mutex;

    unsigned long handshake_timeout;
} sslclientudp_context;


void ssl_init(sslclientudp_context *ssl_client);
int start_ssl_client(sslclientudp_context *ssl_client, const char *host, uint32_t port, int timeout, const char *rootCABuff, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey);
void stop_ssl_socket(sslclientudp_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
int data_to_read(sslclientudp_context *ssl_client);
int send_ssl_data(sslclientudp_context *ssl_client, const uint8_t *data, uint16_t len);
int get_ssl_receive(sslclientudp_context *ssl_client, uint8_t *data, int length);
bool verify_ssl_fingerprint(sslclientudp_context *ssl_client, const char* fp, const char* domain_name);
bool verify_ssl_dn(sslclientudp_context *ssl_client, const char* domain_name);

#endif
