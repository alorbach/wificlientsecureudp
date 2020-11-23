/* Provide SSL/TLS functions to ESP32 with Arduino IDE
*
* Adapted from the ssl_client1 example of mbedtls.
*
* Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
* Additions Copyright (C) 2017 Evandro Luis Copercini, Apache 2.0 License.
*/

#undef MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_SSL_PROTO_DTLS

#include "Arduino.h"
#include <esp32-hal-log.h>
#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include "mbedtls/ssl.h"
#include <mbedtls/sha256.h>
#include <mbedtls/oid.h>
#include <algorithm>
#include <string>
#include "ssl_client_udp.h"
#include "WiFi.h"

const char *TAG = "ssl_client_udp";
const char *persudp = "esp32-tls-udp";

static int _handle_error(int err, const char * file, int line)
{
    if(err == -30848){
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    log_e("[%s():%d]: (%#02X) %s", file, line, err, error_buf);
#else
    log_e("[%s():%d]: code %#02X", file, line, err);
#endif
    return err;
}

static void _handle_debug( void *ctx, int level, const char *file, int line, const char *str ) {
    ((void) level);

    log_d_mbedtls("mbedtls debug in [%s():%d]: %s", file, line, str);
//    fflush(  (FILE *) ctx  );
}

#define handle_error(e) _handle_error(e, __FUNCTION__, __LINE__)

/* --- BEGIN IMPORT FROM MBEDTLLS Library! */
struct _hr_time
{
    struct timeval start;
};

unsigned long my_mbedtls_timing_get_timer( struct mbedtls_timing_hr_time *val, int reset )
{
    struct _hr_time *t = (struct _hr_time *) val;

    if( reset )
    {
        gettimeofday( &t->start, NULL );
        return( 0 );
    }
    else
    {
        unsigned long delta;
        struct timeval now;
        gettimeofday( &now, NULL );
        delta = ( now.tv_sec  - t->start.tv_sec  ) * 1000ul
              + ( now.tv_usec - t->start.tv_usec ) / 1000;
        return( delta );
    }
}
void my_mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if( fin_ms != 0 )
        (void) my_mbedtls_timing_get_timer( &ctx->timer, 1 );
}
int my_mbedtls_timing_get_delay( void *data )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    unsigned long elapsed_ms;

    if( ctx->fin_ms == 0 )
        return( -1 );

    elapsed_ms = my_mbedtls_timing_get_timer( &ctx->timer, 0 );

    if( elapsed_ms >= ctx->fin_ms )
        return( 2 );

    if( elapsed_ms >= ctx->int_ms )
        return( 1 );

    return( 0 );
}
/**/
/* --- END IMPORT FROM MBEDTLLS Library! */

void ssl_init(sslclientudp_context *ssl_client)
{	
#if defined(CONFIG_MBEDTLS_DEBUG)
	// Enable Debug Support
	mbedtls_debug_set_threshold( 0 /* 0=less, 4=Verbose */ );
#endif

	/* Create Mutex for send/receive*/
	ssl_client->mbedtls_mutex = xSemaphoreCreateMutex();

//    mbedtls_net_init(&ssl_client->socket_ctx);
    mbedtls_ssl_init(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_init(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
}


int start_ssl_client(sslclientudp_context *ssl_client, const char *host, uint32_t port, int timeout, const char *rootCABuff, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey)
{
    char buf[512];
    char szPort[16];
    int ret, flags;
    int enable = 1;
	snprintf_P(szPort, 16, PSTR("%d"), port);
    log_d("Free internal heap before TLS %u", ESP.getFreeHeap());

	/* Socket Code */
    ssl_client->socket = -1;
    ssl_client->socket = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ssl_client->socket < 0) {
        log_e("ERROR opening socket");
        return ssl_client->socket;
    }

    IPAddress srv((uint32_t)0);
    if(!WiFiGenericClass::hostByName(host, srv)){
        return -1;
    }
	/**/
	
    log_d("Seeding the random number generator");
    mbedtls_entropy_init(&ssl_client->entropy_ctx);
    ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                &ssl_client->entropy_ctx, (const unsigned char *) persudp, strlen(persudp));
    if (ret < 0) {
        return handle_error(ret);
    }

    if (rootCABuff != NULL) {
        log_i("Loading CA cert");
        mbedtls_x509_crt_init(&ssl_client->ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL /*MBEDTLS_SSL_VERIFY_REQUIRED*/);
        ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);
        mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
        //mbedtls_ssl_conf_verify(&ssl_client->ssl_ctx, my_verify, NULL );
        if (ret < 0) {
            return handle_error(ret);
        }
    } else if (pskIdent != NULL && psKey != NULL) {
        log_i("Setting up PSK");
        // convert PSK from hex to binary
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2*MBEDTLS_PSK_MAX_LEN) {
            log_e("pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey)/2;
        for (int j=0; j<strlen(psKey); j+= 2) {
            char c = psKey[j];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] = c<<4;
            c = psKey[j+1];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] |= c;
        }
        // set mbedtls config
        ret = mbedtls_ssl_conf_psk(&ssl_client->ssl_conf, psk, psk_len,
                 (const unsigned char *)pskIdent, strlen(pskIdent));
        if (ret != 0) {
            log_e("mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        } 
		log_i("mbedtls_ssl_conf_psk set to Ident:'%s', Key:'%s'", pskIdent, psKey);
    } else {
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        log_i("WARNING: Use certificates for a more secure communication!");
    }
	
    if (cli_cert != NULL && cli_key != NULL) {
        mbedtls_x509_crt_init(&ssl_client->client_cert);
        mbedtls_pk_init(&ssl_client->client_key);

        log_i("Loading CRT cert");

        ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
        if (ret < 0) {
            return handle_error(ret);
        }

        log_i("Loading private key");
        ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);

        if (ret != 0) {
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
    }
	
    log_i("Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }
	
	/**/
	log_i("Starting socket");
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = srv;
    serv_addr.sin_port = htons(port);
    if (lwip_connect(ssl_client->socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
        if(timeout <= 0){
            timeout = 30000;
        }
        lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        lwip_setsockopt(ssl_client->socket, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
        lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
    } else {
        log_e("Connect to Server failed!");
        return -1;
    }
    fcntl( ssl_client->socket, F_SETFL, fcntl( ssl_client->socket, F_GETFL, 0 ) | O_NONBLOCK );
	log_i("lwip_connect to %s:%s returned success", host, szPort);
	
	/*
	if( ( ret = mbedtls_net_connect( &ssl_client->socket_ctx, host,
									 szPort, MBEDTLS_NET_PROTO_UDP ) ) != 0 )
	{
        log_e("ERROR connect mbedtls_net_connect returned %d", ret);
        return ret;
	} else
		log_i("mbedtls_net_connect to %s:%s returned success", host, szPort);
	/**/

	
	log_d("Init other mbedtls stuff");
    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);
    mbedtls_ssl_conf_dbg(&ssl_client->ssl_conf, _handle_debug, stdout);	
	mbedtls_ssl_conf_dtls_anti_replay(&ssl_client->ssl_conf, (char) MBEDTLS_SSL_ANTI_REPLAY_ENABLED);
	mbedtls_ssl_conf_renegotiation(&ssl_client->ssl_conf, MBEDTLS_SSL_RENEGOTIATION_ENABLED  );
	
	// ssl_client->handshake_timeout = 20000;
	mbedtls_ssl_conf_handshake_timeout( &ssl_client->ssl_conf, 1000, ssl_client->handshake_timeout );
    if ((ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf)) != 0) {
        return handle_error(ret);
    }

    // Hostname set here should match CN in server certificate
    log_d("Setting hostname for TLS session...");
    if((ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, host)) != 0){
        return handle_error(ret);
	}

//    mbedtls_ssl_set_bio(	&ssl_client->ssl_ctx, &ssl_client->socket, mbedtls_net_send, mbedtls_net_recv, NULL );
    mbedtls_ssl_set_bio(	&ssl_client->ssl_ctx, &ssl_client->socket, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
//    mbedtls_ssl_set_bio(	&ssl_client->ssl_ctx, &ssl_client->socket_ctx, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
	mbedtls_ssl_set_timer_cb( &ssl_client->ssl_ctx, &ssl_client->timer, my_mbedtls_timing_set_delay, my_mbedtls_timing_get_delay );

    log_i("Performing the SSL/TLS handshake (timeout %d)...", ssl_client->handshake_timeout);
    unsigned long handshake_start_time=millis();
	do {
		ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx); 
		// log_i("Performing the SSL/TLS handshake %d ...", millis()-handshake_start_time);
        if((millis()-handshake_start_time) > ssl_client->handshake_timeout /*ssl_client->handshake_timeout*/) {
            log_e("SSL/TLS handshake timeout (%d/%d) ", ssl_client->handshake_timeout, ret);
			handle_error(ret); 
			return -1;
		}
	    vTaskDelay(10 / portTICK_PERIOD_MS);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	if( ret != 0 ) {
		log_e("SSL/TLS handshake fail (%d/%#02X) ", ssl_client->handshake_timeout, ret);
		return handle_error(ret); 
	} else {
		log_i("SSL/TLS handshake SUCCESSFULL");
	}
	
    if (cli_cert != NULL && cli_key != NULL) {
        log_d("Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
        if ((ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx)) >= 0) {
            log_d("Record expansion is %d", ret);
        } else {
            log_w("Record expansion is unknown (compression)");
        }
    }

    log_d("Verifying peer X.509 certificate...");
    if ((flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx)) != 0) {
        bzero(buf, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        log_e("Failed to verify peer certificate! verification info: %s", buf);
        stop_ssl_socket(ssl_client, rootCABuff, cli_cert, cli_key);  //It's not safe continue.
        return handle_error(ret);
    } else {
        log_d("Certificate verified.");
    }
    
    if (rootCABuff != NULL) {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }
    if (cli_cert != NULL) {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
    }
    if (cli_key != NULL) {
        mbedtls_pk_free(&ssl_client->client_key);
    }    

    log_d("Free internal heap after TLS %u", ESP.getFreeHeap());

//    return 0; // Means success
    return ssl_client->socket;
}


void stop_ssl_socket(sslclientudp_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key)
{
    log_v("Cleaning SSL connection.");

	if (ssl_client->socket >= 0) {
        close(ssl_client->socket);
        ssl_client->socket = -1;
    }
    mbedtls_ssl_free(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_free(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_free(&ssl_client->drbg_ctx);
    mbedtls_entropy_free(&ssl_client->entropy_ctx);
}


int data_to_read(sslclientudp_context *ssl_client)
{
	/*
    int ret, res;
    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
    //log_e("RET: %i",ret);   //for low level debug
    res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
    //log_e("RES: %i",res);    //for low level debug
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
		log_e("mbedtls_ssl_read error %d with %d bytes remaining", ret, res);  //for low level debug
        return handle_error(ret);
    }
	*/
    int ret, res;
    res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
	
	if (res > 0) {
		ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
			log_e("data_to_read mbedtls_ssl_read error %d with %d bytes remaining", ret, res);  //for low level debug
			return handle_error(ret);
		}
	} else {
//		log_v("data_to_read mbedtls_ssl_get_bytes_avail: %i",res);    //for low level debug
		return res;
	}
}


int send_ssl_data(sslclientudp_context *ssl_client, const uint8_t *data, uint16_t len)
{
    log_v("Writing %d bytes of data to DTLS Stream...", len);  //for low level debug
    int ret = -1;

	// Release MUTEX to be save first
	xSemaphoreGive(ssl_client->mbedtls_mutex);
	
	// Lock MUTEX 
	if( xSemaphoreTake( ssl_client->mbedtls_mutex, ( TickType_t ) 1 ) ) {
		// Send data while available
		do {
			ret = mbedtls_ssl_write( &ssl_client->ssl_ctx, data, len );
		} while( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE );

		// Release MUTEX 
		xSemaphoreGive( ssl_client->mbedtls_mutex );

		// Check for return code
		if( ret < 0 ) {
			log_e("Writing %d bytes of data to DTLS Stream FAILED with ret %d", len, ret);  //for low level debug
			return handle_error(ret);
		}
		/*
		while ((ret = mbedtls_ssl_write(&ssl_client->ssl_ctx, data, len)) <= 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				log_e("Writing %d bytes of data to DTLS Stream FAILED", len);  //for low level debug
				return handle_error(ret);
			}
		}
		*/

		len = ret;
		log_v("%d bytes written to DTLS Stream", len);  //for low level debug
		return ret;
	} else {
		log_e("xSemaphoreTake Failed to lock mutex, skip");
		return 0;
	}
		
}

int get_ssl_receive(sslclientudp_context *ssl_client, uint8_t *data, int length)
{
    int ret = -1;

    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, data, length);
    log_v("Read %d bytes of data from  DTLS Stream...", ret);  //for low level debug
    return ret;
}

static bool parseHexNibble(char pb, uint8_t* res)
{
    if (pb >= '0' && pb <= '9') {
        *res = (uint8_t) (pb - '0'); return true;
    } else if (pb >= 'a' && pb <= 'f') {
        *res = (uint8_t) (pb - 'a' + 10); return true;
    } else if (pb >= 'A' && pb <= 'F') {
        *res = (uint8_t) (pb - 'A' + 10); return true;
    }
    return false;
}

// Compare a name from certificate and domain name, return true if they match
static bool matchName(const std::string& name, const std::string& domainName)
{
    size_t wildcardPos = name.find('*');
    if (wildcardPos == std::string::npos) {
        // Not a wildcard, expect an exact match
        return name == domainName;
    }

    size_t firstDotPos = name.find('.');
    if (wildcardPos > firstDotPos) {
        // Wildcard is not part of leftmost component of domain name
        // Do not attempt to match (rfc6125 6.4.3.1)
        return false;
    }
    if (wildcardPos != 0 || firstDotPos != 1) {
        // Matching of wildcards such as baz*.example.com and b*z.example.com
        // is optional. Maybe implement this in the future?
        return false;
    }
    size_t domainNameFirstDotPos = domainName.find('.');
    if (domainNameFirstDotPos == std::string::npos) {
        return false;
    }
    return domainName.substr(domainNameFirstDotPos) == name.substr(firstDotPos);
}

// Verifies certificate provided by the peer to match specified SHA256 fingerprint
bool verify_ssl_fingerprint(sslclientudp_context *ssl_client, const char* fp, const char* domain_name)
{
    // Convert hex string to byte array
    uint8_t fingerprint_local[32];
    int len = strlen(fp);
    int pos = 0;
    for (size_t i = 0; i < sizeof(fingerprint_local); ++i) {
        while (pos < len && ((fp[pos] == ' ') || (fp[pos] == ':'))) {
            ++pos;
        }
        if (pos > len - 2) {
            log_d("pos:%d len:%d fingerprint too short", pos, len);
            return false;
        }
        uint8_t high, low;
        if (!parseHexNibble(fp[pos], &high) || !parseHexNibble(fp[pos+1], &low)) {
            log_d("pos:%d len:%d invalid hex sequence: %c%c", pos, len, fp[pos], fp[pos+1]);
            return false;
        }
        pos += 2;
        fingerprint_local[i] = low | (high << 4);
    }

    // Get certificate provided by the peer
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

    if (!crt)
    {
        log_d("could not fetch peer certificate");
        return false;
    }

    // Calculate certificate's SHA256 fingerprint
    uint8_t fingerprint_remote[32];
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, false);
    mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
    mbedtls_sha256_finish(&sha256_ctx, fingerprint_remote);

    // Check if fingerprints match
    if (memcmp(fingerprint_local, fingerprint_remote, 32))
    {
        log_d("fingerprint doesn't match");
        return false;
    }

    // Additionally check if certificate has domain name if provided
    if (domain_name)
        return verify_ssl_dn(ssl_client, domain_name);
    else
        return true;
}

// Checks if peer certificate has specified domain in CN or SANs
bool verify_ssl_dn(sslclientudp_context *ssl_client, const char* domain_name)
{
    log_d("domain name: '%s'", (domain_name)?domain_name:"(null)");
    std::string domain_name_str(domain_name);
    std::transform(domain_name_str.begin(), domain_name_str.end(), domain_name_str.begin(), ::tolower);

    // Get certificate provided by the peer
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

    // Check for domain name in SANs
    const mbedtls_x509_sequence* san = &crt->subject_alt_names;
    while (san != nullptr)
    {
        std::string san_str((const char*)san->buf.p, san->buf.len);
        std::transform(san_str.begin(), san_str.end(), san_str.begin(), ::tolower);

        if (matchName(san_str, domain_name_str))
            return true;

        log_d("SAN '%s': no match", san_str.c_str());

        // Fetch next SAN
        san = san->next;
    }

    // Check for domain name in CN
    const mbedtls_asn1_named_data* common_name = &crt->subject;
    while (common_name != nullptr)
    {
        // While iterating through DN objects, check for CN object
        if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &common_name->oid))
        {
            std::string common_name_str((const char*)common_name->val.p, common_name->val.len);

            if (matchName(common_name_str, domain_name_str))
                return true;

            log_d("CN '%s': not match", common_name_str.c_str());
        }

        // Fetch next DN object
        common_name = common_name->next;
    }

    return false;
}
