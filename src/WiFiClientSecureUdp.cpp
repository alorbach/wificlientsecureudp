/*
  WiFiClientSecureUdp.cpp - Client Secure class for ESP32
  Copyright (c) 2016 Hristo Gochkov  All right reserved.
  Additions Copyright (C) 2017 Evandro Luis Copercini.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "WiFiClientSecureUdp.h"
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

#undef connect
#undef write
#undef read


WiFiClientSecureUdp::WiFiClientSecureUdp()
{
    _connected = false;

    sslclient = new sslclientudp_context;
    ssl_init(sslclient);
    sslclient->socket = -1;
    sslclient->handshake_timeout = 120000;
    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    next = NULL;
}


WiFiClientSecureUdp::WiFiClientSecureUdp(int sock)
{
    _connected = false;
    _timeout = 0;

    sslclient = new sslclientudp_context;
    ssl_init(sslclient);
    sslclient->socket = sock;
    sslclient->handshake_timeout = 120000;
	
    if (sock >= 0) {
        _connected = true;
    }

    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    next = NULL;
}

WiFiClientSecureUdp::~WiFiClientSecureUdp()
{
    stop();

	/* Delete Mutex for send/receive 
	if (sslclient->mbedtls_mutex != NULL) {
        vSemaphoreDelete(sslclient->mbedtls_mutex);  // Delete
    }
	*/
	
    delete sslclient;
}

WiFiClientSecureUdp &WiFiClientSecureUdp::operator=(const WiFiClientSecureUdp &other)
{
    stop();
    sslclient->socket = other.sslclient->socket;
    _connected = other._connected;
    return *this;
}

void WiFiClientSecureUdp::stop()
{
	log_d("stop called");
    stop_ssl_socket(sslclient, _CA_cert, _cert, _private_key);
    if (sslclient->socket >= 0) {
        close(sslclient->socket);
        sslclient->socket = -1;
    }
	_connected = false;
	_peek = -1;
}

int WiFiClientSecureUdp::connect(IPAddress ip, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(ip, port, _pskIdent, _psKey);
    return connect(ip, port, _CA_cert, _cert, _private_key);
}

int WiFiClientSecureUdp::connect(IPAddress ip, uint16_t port, int32_t timeout){
    _timeout = timeout;
    return connect(ip, port);
}

int WiFiClientSecureUdp::connect(const char *host, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(host, port, _pskIdent, _psKey);
    return connect(host, port, _CA_cert, _cert, _private_key);
}

int WiFiClientSecureUdp::connect(const char *host, uint16_t port, int32_t timeout){
    _timeout = timeout;
    return connect(host, port);
}

int WiFiClientSecureUdp::connect(IPAddress ip, uint16_t port, const char *_CA_cert, const char *_cert, const char *_private_key)
{
    return connect(ip.toString().c_str(), port, _CA_cert, _cert, _private_key);
}

int WiFiClientSecureUdp::connect(const char *host, uint16_t port, const char *_CA_cert, const char *_cert, const char *_private_key)
{
    if(_timeout > 0 && sslclient->handshake_timeout != 0){
        sslclient->handshake_timeout = _timeout;
    }
    int ret = start_ssl_client(sslclient, host, port, _timeout, _CA_cert, _cert, _private_key, NULL, NULL);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: error %#02X", ret);
        stop();
        return 0;
    } else {
        log_d("start_ssl_client: success %#02X", ret);
    }
    _connected = true;
    return 1;
}

int WiFiClientSecureUdp::connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey) {
    return connect(ip.toString().c_str(), port,_pskIdent, _psKey);
}

int WiFiClientSecureUdp::connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey) {
    log_d("start_ssl_client with PSK");
    if(_timeout > 0 && sslclient->handshake_timeout != 0){
        sslclient->handshake_timeout = _timeout;
    }
    int ret = start_ssl_client(sslclient, host, port, _timeout, NULL, NULL, NULL, _pskIdent, _psKey);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: error %#02X", ret);
        stop();
        return 0;
    } else {
        log_d("start_ssl_client: success %#02X", ret);
	}
    _connected = true;
    return 1;
}

int WiFiClientSecureUdp::peek(){
    if(_peek >= 0){
        return _peek;
    }
    _peek = timedRead();
    return _peek;
}

size_t WiFiClientSecureUdp::write(uint8_t data)
{
    return write(&data, 1);
}

int WiFiClientSecureUdp::read()
{
    uint8_t data = -1;
    int res = read(&data, 1);
    if (res < 0) {
        return res;
    }
    return data;
}

size_t WiFiClientSecureUdp::write(const uint8_t *buf, size_t size)
{
    if (!_connected) {
        return 0;
    }
	int res = send_ssl_data(sslclient, buf, size);
	if (res < 0) {
		if (_writeFailTimeout > 0) {
			unsigned long currentTime = millis();
			if (_writeLastFail == 0) {
				_writeLastFail = currentTime;
			} else if ( (currentTime - _writeLastFail) > _writeFailTimeout) {
				handle_error_mbedtls(res);
				log_e("send_ssl_data failed after %d ms with res %#02X, tear down session!", _writeFailTimeout, res);
				stop();
			}
			if (_writeFailDelay > 0)
				vTaskDelay(_writeFailDelay / portTICK_PERIOD_MS);
		} else {
			log_e("send_ssl_data failed with res %#02X, tear down session!", res);
			stop();
		}
		res = 0;
	} else {
		if (_writeLastFail > 0) {
			log_w("send_ssl_data recovered session after %d ms", (millis() - _writeLastFail));
			_writeLastFail = 0;
		}
	}
	return res;
}

int WiFiClientSecureUdp::read(uint8_t *buf, size_t size)
{
    int peeked = 0;
    int avail = available();
    if ((!buf && size) || avail <= 0) {
        return -1;
    }
    if(!size){
        return 0;
    }
    if(_peek >= 0){
        buf[0] = _peek;
        _peek = -1;
        size--;
        avail--;
        if(!size || !avail){
            return 1;
        }
        buf++;
        peeked = 1;
    }
    
    int res = get_ssl_receive(sslclient, buf, size);
    if (res < 0) {
		log_e("get_ssl_receive fail res %#02X ", res);
        stop();
        return peeked?peeked:res;
    }
    return res + peeked;
}

int WiFiClientSecureUdp::available()
{
    int peeked = (_peek >= 0);
    if (!_connected) {
        return peeked;
    }
    int res = data_to_read(sslclient);
    if (res < 0) {
		log_e("data_to_read fail res %#02X ", res);
        stop();
        return peeked?peeked:res;
    }
    return res+peeked;
}

uint8_t WiFiClientSecureUdp::connected()
{
    uint8_t dummy = 0;
    read(&dummy, 0);

    return _connected;
}

void WiFiClientSecureUdp::setCACert (const char *rootCA)
{
    _CA_cert = rootCA;
}

void WiFiClientSecureUdp::setCertificate (const char *client_ca)
{
    _cert = client_ca;
}

void WiFiClientSecureUdp::setPrivateKey (const char *private_key)
{
    _private_key = private_key;
}

void WiFiClientSecureUdp::setPreSharedKey(const char *pskIdent, const char *psKey) {
    _pskIdent = pskIdent;
    _psKey = psKey;
}

void WiFiClientSecureUdp::setwriteFailTimeout (int newWriteFailTimeout)
{
	_writeFailTimeout = newWriteFailTimeout;
	_writeLastFail = 0; 
}

void WiFiClientSecureUdp::setwriteFailDelay (int newwriteFailDelay)
{
	_writeFailDelay = newwriteFailDelay;
}

bool WiFiClientSecureUdp::verify(const char* fp, const char* domain_name)
{
    if (!sslclient)
        return false;

    return verify_ssl_fingerprint(sslclient, fp, domain_name);
}

char *WiFiClientSecureUdp::_streamLoad(Stream& stream, size_t size) {
  static char *dest = nullptr;
  if(dest) {
      free(dest);
  }
  dest = (char*)malloc(size);
  if (!dest) {
    return nullptr;
  }
  if (size != stream.readBytes(dest, size)) {
    free(dest);
    dest = nullptr;
  }
  return dest;
}

bool WiFiClientSecureUdp::loadCACert(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCACert(dest);
    ret = true;
  }
  return ret;
}

bool WiFiClientSecureUdp::loadCertificate(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCertificate(dest);
    ret = true;
  }
  return ret;
}

bool WiFiClientSecureUdp::loadPrivateKey(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setPrivateKey(dest);
    ret = true;
  }
  return ret;
}

int WiFiClientSecureUdp::lastError(char *buf, const size_t size)
{
    if (!_lastError) {
        return 0;
    }
    char error_buf[100];
    mbedtls_strerror(_lastError, error_buf, 100);
    snprintf(buf, size, "%s", error_buf);
    return _lastError;
}

void WiFiClientSecureUdp::setHandshakeTimeout(unsigned long handshake_timeout)
{
    sslclient->handshake_timeout = handshake_timeout * 1000;
	log_d("setHandshakeTimeout: %d", sslclient->handshake_timeout);
}
