/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils/common/tls.h"
#include "utils/common/cert.h"
#include "utils/common/msg.h"
#include "contrib/base64.h"
#include "libknot/errcode.h"

void tls_params_init(tls_params_t *params)
{
	if (params == NULL) {
		return;
	}

	memset(params, 0, sizeof(*params));

	init_list(&params->ca_files);
	init_list(&params->pins);
}

int tls_params_copy(tls_params_t *dst, const tls_params_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	tls_params_init(dst);

	dst->enable = src->enable;
	dst->system_ca = src->system_ca;
	if (src->hostname != NULL) {
		dst->hostname = strdup(src->hostname);
		if (dst->hostname == NULL) {
			tls_params_clean(dst);
			return KNOT_ENOMEM;
		}
	}

	ptrnode_t *n = NULL;
	WALK_LIST(n, src->ca_files) {
		char *src_file = (char *)n->d;
		char *file = strdup(src_file);
		if (file == NULL || ptrlist_add(&dst->ca_files, file, NULL) == NULL) {
			tls_params_clean(dst);
			return KNOT_ENOMEM;
		}
	}
	WALK_LIST(n, src->pins) {
		uint8_t *src_pin = (uint8_t *)n->d;
		uint8_t *pin = malloc(1 + src_pin[0]);
		if (pin == NULL || ptrlist_add(&dst->pins, pin, NULL) == NULL) {
			tls_params_clean(dst);
			return KNOT_ENOMEM;
		}
		memcpy(pin, src_pin, 1 + src_pin[0]);
	}

	return KNOT_EOK;
}

void tls_params_clean(tls_params_t *params)
{
	if (params == NULL) {
		return;
	}

	ptrnode_t *node = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(node, nxt, params->ca_files) {
		free(node->d);
	}
	ptrlist_free(&params->ca_files, NULL);

	WALK_LIST_DELSAFE(node, nxt, params->pins) {
		free(node->d);
	}
	ptrlist_free(&params->pins, NULL);

	free(params->hostname);

	memset(params, 0, sizeof(*params));
}

static bool check_pin(const uint8_t *cert_pin, size_t cert_pin_len, const list_t *pins)
{
	if (EMPTY_LIST(*pins)) {
		return false;
	}

	ptrnode_t *n = NULL;
	WALK_LIST(n, *pins) {
		uint8_t *pin = (uint8_t *)n->d;
		if (pin[0] == cert_pin_len &&
		    memcmp(cert_pin, &pin[1], cert_pin_len) == 0) {
			return true;
		}
	}

	return false;
}

static int check_certificates(gnutls_session_t session, const list_t *pins)
{
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		DBG("TLS, invalid certificate type\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	unsigned cert_list_size;
	const gnutls_datum_t *cert_list =
		gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list == NULL || cert_list_size == 0) {
		DBG("TLS, empty certificate list\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	size_t matches = 0;

	DBG("TLS, received certificate hierarchy:\n");
	for (int i = 0; i < cert_list_size; i++) {
		gnutls_x509_crt_t cert;
		int ret = gnutls_x509_crt_init(&cert);
		if (ret != GNUTLS_E_SUCCESS) {
			return ret;
		}

		ret = gnutls_x509_crt_import(cert, &cert_list[i], GNUTLS_X509_FMT_DER);
		if (ret != GNUTLS_E_SUCCESS) {
			gnutls_x509_crt_deinit(cert);
			return ret;
		}

		gnutls_datum_t cert_name = { 0 };
		ret = gnutls_x509_crt_get_dn2(cert, &cert_name);
		if (ret != GNUTLS_E_SUCCESS) {
			gnutls_x509_crt_deinit(cert);
			return ret;
		}
		DBG(" #%i, %s\n", i + 1, cert_name.data);
		gnutls_free(cert_name.data);

		uint8_t cert_pin[CERT_PIN_LEN] = { 0 };
		ret = cert_get_pin(cert, cert_pin, sizeof(cert_pin));
		if (ret != KNOT_EOK) {
			gnutls_x509_crt_deinit(cert);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}

		// Check if correspond to a specified PIN.
		bool match = check_pin(cert_pin, sizeof(cert_pin), pins);
		if (match) {
			matches++;
		}

		uint8_t *txt_pin;
		ret = base64_encode_alloc(cert_pin, sizeof(cert_pin), &txt_pin);
		if (ret < 0) {
			gnutls_x509_crt_deinit(cert);
			return ret;
		}
		DBG("     SHA-256 PIN: %.*s%s\n", ret, txt_pin, match ? ", MATCH" : "");
		free(txt_pin);

		gnutls_x509_crt_deinit(cert);
	}

	if (matches > 0) {
		return GNUTLS_E_SUCCESS;
	} else if (EMPTY_LIST(*pins)) {
		DBG("TLS, skipping certificate PIN check\n");
		return GNUTLS_E_SUCCESS;
	} else {
		DBG("TLS, no certificate PIN match\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
}

static bool do_verification(const tls_params_t *params)
{
	return params->hostname != NULL || params->system_ca ||
	       !EMPTY_LIST(params->ca_files);
}

static int verify_certificate(gnutls_session_t session)
{
	tls_ctx_t *ctx = gnutls_session_get_ptr(session);

	// Check for pinned certificates and print certificate hierarchy.
	int ret = check_certificates(session, &ctx->params->pins);
	if (ret != GNUTLS_E_SUCCESS) {
		return ret;
	}

	if (!do_verification(ctx->params)) {
		DBG("TLS, skipping certificate verification\n");
		return GNUTLS_E_SUCCESS;
	}

	// Set server certificate check.
	gnutls_typed_vdata_st data[2] = {
		{ .type = GNUTLS_DT_KEY_PURPOSE_OID,
		  .data = (void *)GNUTLS_KP_TLS_WWW_SERVER },
		{ .type = GNUTLS_DT_DNS_HOSTNAME,
		  .data = (void *)ctx->params->hostname }
	};
	size_t data_count = (ctx->params->hostname != NULL) ? 2 : 1;

	unsigned int status;
	ret = gnutls_certificate_verify_peers(session, data, data_count, &status);
	if (ret != GNUTLS_E_SUCCESS) {
		WARN("TLS, failed to verify peer certificate\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_datum_t msg;
	ret = gnutls_certificate_verification_status_print(
		status, gnutls_certificate_type_get(session), &msg, 0);
	if (ret == GNUTLS_E_SUCCESS) {
		DBG("TLS, %s\n", msg.data);
	}
	gnutls_free(msg.data);

	return (status == 0) ? GNUTLS_E_SUCCESS : GNUTLS_E_CERTIFICATE_ERROR;
}

int tls_ctx_init(tls_ctx_t *ctx, const tls_params_t *params, int wait)
{
	if (ctx == NULL || params == NULL || !params->enable) {
		return KNOT_EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->params = params;
	ctx->wait = wait;

	int ret = gnutls_certificate_allocate_credentials(&ctx->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	// Import system certificates.
	if (ctx->params->system_ca ||
	    (ctx->params->hostname != NULL && EMPTY_LIST(ctx->params->ca_files))) {
		ret = gnutls_certificate_set_x509_system_trust(ctx->credentials);
		if (ret < 0) {
			WARN("TLS, failed to import system certificates (%s)\n",
			     gnutls_strerror_name(ret));
			return KNOT_ERROR;
		} else {
			DBG("TLS, imported %i system certificates\n", ret);
		}
	}

	// Import provided certificate files.
	ptrnode_t *n = NULL;
	WALK_LIST(n, ctx->params->ca_files) {
		const char *file = (char *)n->d;
		ret = gnutls_certificate_set_x509_trust_file(ctx->credentials, file,
		                                             GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			WARN("TLS, failed to import certificate file '%s' (%s)\n",
			    file, gnutls_strerror_name(ret));
			return KNOT_ERROR;
		} else {
			DBG("TLS, imported %i certificates from '%s'\n", ret, file);
		}
	}

	gnutls_certificate_set_verify_function(ctx->credentials, verify_certificate);

	return KNOT_EOK;
}

int tls_ctx_connect(tls_ctx_t *ctx, int sockfd,  const char *remote)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int ret = gnutls_init(&ctx->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	ret = gnutls_set_default_priority(ctx->session);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	ret = gnutls_credentials_set(ctx->session, GNUTLS_CRD_CERTIFICATE,
	                             ctx->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	if (remote != NULL) {
		ret = gnutls_server_name_set(ctx->session, GNUTLS_NAME_DNS, remote,
		                             strlen(remote));
		if (ret != GNUTLS_E_SUCCESS) {
			return KNOT_NET_ECONNECT;
		}
	}

	gnutls_session_set_ptr(ctx->session, ctx);
	gnutls_transport_set_int(ctx->session, sockfd);
	gnutls_handshake_set_timeout(ctx->session, 1000 * ctx->wait);

	// Perform the TLS handshake
	do {
		ret = gnutls_handshake(ctx->session);
	} while (ret != GNUTLS_E_SUCCESS && gnutls_error_is_fatal(ret) == 0);
	if (ret != GNUTLS_E_SUCCESS) {
		WARN("TLS, handshake failed (%s)\n", gnutls_strerror(ret));
		tls_ctx_close(ctx);
		return KNOT_NET_ESOCKET;
	}

	return KNOT_EOK;
}

int tls_ctx_send(tls_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	uint16_t msg_len = htons(buf_len);

	gnutls_record_cork(ctx->session);

	if (gnutls_record_send(ctx->session, &msg_len, sizeof(msg_len)) <= 0) {
		WARN("TLS, failed to send\n");
		return KNOT_NET_ESEND;
	}
	if (gnutls_record_send(ctx->session, buf, buf_len) <= 0) {
		WARN("TLS, failed to send\n");
		return KNOT_NET_ESEND;
	}

	while (gnutls_record_check_corked(ctx->session) > 0) {
		int ret = gnutls_record_uncork(ctx->session, 0);
		if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
			WARN("TLS, failed to send (%s)\n", gnutls_strerror(ret));
			return KNOT_NET_ESEND;
		}
	}

	return KNOT_EOK;
}

int tls_ctx_receive(tls_ctx_t *ctx, uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	uint32_t total = 0;

	uint16_t msg_len = 0;
	// Receive message header.
	while (total < sizeof(msg_len)) {
		ssize_t ret = gnutls_record_recv(ctx->session, &msg_len + total,
		                                 sizeof(msg_len) - total);
		if (ret > 0) {
			total += ret;
		} else if (ret == 0) {
			WARN("TLS, peer has closed the connection\n");
			return KNOT_NET_ERECV;
		} else if (gnutls_error_is_fatal(ret) != 0) {
			WARN("TLS, failed to receive reply (%s)\n",
			     gnutls_strerror(ret));
			return KNOT_NET_ERECV;
		}
	}

	// Convert number to host format.
	msg_len = ntohs(msg_len);
	if (msg_len > buf_len) {
		return KNOT_ESPACE;
	}

	total = 0;

	// Receive data over TLS
	while (total < msg_len) {
		ssize_t ret = gnutls_record_recv(ctx->session, buf + total,
		                                 msg_len - total);
		if (ret > 0) {
			total += ret;
		} else if (ret == 0) {
			WARN("TLS, peer has closed the connection\n");
			return KNOT_NET_ERECV;
		} else if (gnutls_error_is_fatal(ret) != 0) {
			WARN("TLS, failed to receive reply (%s)\n",
			     gnutls_strerror(ret));
			return KNOT_NET_ERECV;
		}
	}

	return total;
}

void tls_ctx_close(tls_ctx_t *ctx)
{
	if (ctx == NULL || ctx->session == NULL) {
		return;
	}

	gnutls_bye(ctx->session, GNUTLS_SHUT_RDWR);
}

void tls_ctx_deinit(tls_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->session != NULL) {
		gnutls_deinit(ctx->session);
	}

	if (ctx->credentials != NULL) {
		gnutls_certificate_free_credentials(ctx->credentials);
	}
}

void print_tls(const tls_ctx_t *ctx)
{
	if (ctx == NULL || ctx->session == NULL) {
		return;
	}

	char *msg = gnutls_session_get_desc(ctx->session);
	printf(";; TLS session %s\n", msg);
	gnutls_free(msg);
}
