/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <poll.h>
#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>
#include <gnutls/x509.h>
#define GNUTLS_VERSION_FASTOPEN_READY 0x030503
#if GNUTLS_VERSION_NUMBER >= GNUTLS_VERSION_FASTOPEN_READY
#include <gnutls/socket.h>
#endif

#include "utils/common/tls.h"
#include "utils/common/cert.h"
#include "utils/common/msg.h"
#include "contrib/base64.h"
#include "libknot/errcode.h"

const gnutls_datum_t dot_alpn = {
	(unsigned char *)"dot", 3
};

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

	if (src->sni != NULL) {
		dst->sni = strdup(src->sni);
		if (dst->sni == NULL) {
			tls_params_clean(dst);
			return KNOT_ENOMEM;
		}
	}

	if (src->keyfile != NULL) {
		dst->keyfile = strdup(src->keyfile);
		if (dst->keyfile == NULL) {
			tls_params_clean(dst);
			return KNOT_ENOMEM;
		}
	}

	if (src->certfile != NULL) {
		dst->certfile = strdup(src->certfile);
		if (dst->certfile == NULL) {
			tls_params_clean(dst);
			return KNOT_ENOMEM;
		}
	}

	dst->ocsp_stapling = src->ocsp_stapling;

	ptrnode_t *n;
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

	ptrnode_t *node, *nxt;
	WALK_LIST_DELSAFE(node, nxt, params->ca_files) {
		free(node->d);
	}
	ptrlist_free(&params->ca_files, NULL);

	WALK_LIST_DELSAFE(node, nxt, params->pins) {
		free(node->d);
	}
	ptrlist_free(&params->pins, NULL);

	free(params->hostname);
	free(params->sni);
	free(params->keyfile);
	free(params->certfile);

	memset(params, 0, sizeof(*params));
}

static bool check_pin(const uint8_t *cert_pin, size_t cert_pin_len, const list_t *pins)
{
	if (EMPTY_LIST(*pins)) {
		return false;
	}

	ptrnode_t *n;
	WALK_LIST(n, *pins) {
		uint8_t *pin = (uint8_t *)n->d;
		if (pin[0] == cert_pin_len &&
		    memcmp(cert_pin, &pin[1], cert_pin_len) == 0) {
			return true;
		}
	}

	return false;
}

static bool verify_ocsp(gnutls_session_t *session)
{
	bool ret = false;

	gnutls_ocsp_resp_t ocsp_resp;
	bool deinit_ocsp_resp = false;

	gnutls_x509_crt_t server_cert;
	bool deinit_server_cert = false;

	gnutls_certificate_credentials_t xcred;
	bool deinit_xcreds = false;

	gnutls_x509_crt_t issuer_cert;
	bool deinit_issuer_cert = false;

	gnutls_datum_t ocsp_resp_raw;
	if (gnutls_ocsp_status_request_get(*session, &ocsp_resp_raw) != GNUTLS_E_SUCCESS) {
		WARN("TLS, unable to retrieve stapled OCSP data");
		goto cleanup;
	}
	if (gnutls_ocsp_resp_init(&ocsp_resp) != GNUTLS_E_SUCCESS) {
		WARN("TLS, unable to init OCSP data");
		goto cleanup;
	}
	deinit_ocsp_resp = true;
	if (gnutls_ocsp_resp_import(ocsp_resp, &ocsp_resp_raw) != GNUTLS_E_SUCCESS) {
		WARN("TLS, unable to import OCSP response");
		goto cleanup;
	}

	unsigned int cert_list_size = 0;
	const gnutls_datum_t *cert_list = gnutls_certificate_get_peers(*session, &cert_list_size);
	if (cert_list_size == 0) {
		WARN("TLS, unable to retrieve peer certs when verifying OCSP");
		goto cleanup;
	}
	if (gnutls_x509_crt_init(&server_cert) != GNUTLS_E_SUCCESS) {
		WARN("TLS, unable to init server cert when verifying OCSP");
		goto cleanup;
	}
	deinit_server_cert = true;
	if (gnutls_x509_crt_import(server_cert, &cert_list[0], GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
		WARN("TLS, unable to import server cert when verifying OCSP");
		goto cleanup;
	}

	if (gnutls_certificate_allocate_credentials(&xcred) != GNUTLS_E_SUCCESS) {
		WARN("TLS, unable to allocate credentials when verifying OCSP");
		goto cleanup;
	}
	deinit_xcreds = true;

	if (gnutls_certificate_get_issuer(xcred, server_cert, &issuer_cert, 0) != GNUTLS_E_SUCCESS) {
		if (cert_list_size < 2) {
			WARN("TLS, unable to get issuer (CA) cert when verifying OCSP");
			goto cleanup;
		}
		if (gnutls_x509_crt_init(&issuer_cert) != GNUTLS_E_SUCCESS) {
			WARN("TLS, unable to init issuer cert when verifying OCSP");
			goto cleanup;
		}
		deinit_issuer_cert = true;
		if (gnutls_x509_crt_import(issuer_cert, &cert_list[1], GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
			WARN("TLS, unable to import issuer cert when verifying OCSP");
			goto cleanup;
		}
	}

	unsigned int status;
	time_t this_upd, next_upd, now = time(0);
	if (gnutls_ocsp_resp_check_crt(ocsp_resp, 0, server_cert) != GNUTLS_E_SUCCESS) {
		WARN("TLS, OCSP response either empty or not for provided server cert");
		goto cleanup;
	}
	if (gnutls_ocsp_resp_verify_direct(ocsp_resp, issuer_cert, &status, 0) != GNUTLS_E_SUCCESS) {
		WARN("TLS, unable to verify OCSP response against issuer cert");
		goto cleanup;
	}
	if (status != 0) {
		WARN("TLS, got a non-zero status when verifying OCSP response against issuer cert");
		goto cleanup;
	}
	if (gnutls_ocsp_resp_get_single(ocsp_resp, 0, NULL, NULL, NULL, NULL, &status,
	                                &this_upd, &next_upd, NULL, NULL) != GNUTLS_E_SUCCESS) {
		WARN("TLS, error reading OCSP response");
		goto cleanup;
	}
	if (status == GNUTLS_OCSP_CERT_REVOKED) {
		WARN("TLS, OCSP data shows that cert was revoked");
		goto cleanup;
	}
	if (next_upd == -1) {
		tls_ctx_t *ctx = gnutls_session_get_ptr(*session);
		assert(now >= this_upd);
		assert(ctx->params->ocsp_stapling > 0);
		if (now - this_upd > ctx->params->ocsp_stapling) {
			WARN("TLS, OCSP response is out of date.");
			goto cleanup;
		}
	} else {
		if (next_upd < now) {
			WARN("TLS, a newer OCSP response is available but was not sent");
			goto cleanup;
		}
	}

	// Only if we get here is the ocsp result completely valid.
	ret = true;

cleanup:
	if (deinit_issuer_cert) {
		gnutls_x509_crt_deinit(issuer_cert);
	}
	if (deinit_xcreds) {
		gnutls_certificate_free_credentials(xcred);
	}
	if (deinit_server_cert) {
		gnutls_x509_crt_deinit(server_cert);
	}
	if (deinit_ocsp_resp) {
		gnutls_ocsp_resp_deinit(ocsp_resp);
	}

	return ret;
}

static int check_certificates(gnutls_session_t session, const list_t *pins)
{
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		DBG("TLS, invalid certificate type");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	unsigned cert_list_size;
	const gnutls_datum_t *cert_list =
		gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list == NULL || cert_list_size == 0) {
		DBG("TLS, empty certificate list");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	size_t matches = 0;

	DBG("TLS, received certificate hierarchy:");
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
		DBG(" #%i, %s", i + 1, cert_name.data);
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
		ret = knot_base64_encode_alloc(cert_pin, sizeof(cert_pin), &txt_pin);
		if (ret < 0) {
			gnutls_x509_crt_deinit(cert);
			return ret;
		}
		DBG("     SHA-256 PIN: %.*s%s", ret, txt_pin, match ? ", MATCH" : "");
		free(txt_pin);

		gnutls_x509_crt_deinit(cert);
	}

	if (matches > 0) {
		return GNUTLS_E_SUCCESS;
	} else if (EMPTY_LIST(*pins)) {
		DBG("TLS, skipping certificate PIN check");
		return GNUTLS_E_SUCCESS;
	} else {
		DBG("TLS, no certificate PIN match");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
}

static bool do_verification(const tls_params_t *params)
{
	return params->hostname != NULL || params->system_ca ||
	       !EMPTY_LIST(params->ca_files) || params->ocsp_stapling > 0;
}

int tls_certificate_verification(tls_ctx_t *ctx)
{
	gnutls_session_t session = ctx->session;
	// Check for pinned certificates and print certificate hierarchy.
	int ret = check_certificates(session, &ctx->params->pins);
	if (ret != GNUTLS_E_SUCCESS) {
		return ret;
	}

	if (!do_verification(ctx->params)) {
		DBG("TLS, skipping certificate verification");
		return GNUTLS_E_SUCCESS;
	}

	if (ctx->params->ocsp_stapling > 0 && !verify_ocsp(&session)) {
		WARN("TLS, failed to validate required OCSP data");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	// Set server certificate check.
	gnutls_typed_vdata_st data[2] = {
		{ .type = GNUTLS_DT_KEY_PURPOSE_OID,
		  .data = (void *)GNUTLS_KP_TLS_WWW_SERVER },
		{ .type = GNUTLS_DT_DNS_HOSTNAME,
		  .data = (void *)ctx->params->hostname }
	};
	size_t data_count = (ctx->params->hostname != NULL) ? 2 : 1;
	if (data_count == 1) {
		WARN("TLS, no hostname provided, will not verify certificate owner")
	}

	unsigned int status;
	ret = gnutls_certificate_verify_peers(session, data, data_count, &status);
	if (ret != GNUTLS_E_SUCCESS) {
		WARN("TLS, failed to verify peer certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_datum_t msg;
	ret = gnutls_certificate_verification_status_print(
		status, gnutls_certificate_type_get(session), &msg, 0);
	if (ret == GNUTLS_E_SUCCESS) {
		DBG("TLS, %s", msg.data);
	}
	gnutls_free(msg.data);

	if (status != 0) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	return GNUTLS_E_SUCCESS;
}

static int verify_certificate(gnutls_session_t session)
{
	tls_ctx_t *ctx = gnutls_session_get_ptr(session);
	return tls_certificate_verification(ctx);
}

int tls_ctx_init(tls_ctx_t *ctx, const tls_params_t *params,
        unsigned int flags, int wait)

{
	if (ctx == NULL || params == NULL || !params->enable) {
		return KNOT_EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->params = params;
	ctx->wait = wait;
	ctx->sockfd = -1;

	int ret = gnutls_certificate_allocate_credentials(&ctx->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	// Import system certificates.
	if (ctx->params->system_ca ||
	    (ctx->params->hostname != NULL && EMPTY_LIST(ctx->params->ca_files))) {
		ret = gnutls_certificate_set_x509_system_trust(ctx->credentials);
		if (ret < 0) {
			WARN("TLS, failed to import system certificates (%s)",
			     gnutls_strerror_name(ret));
			return KNOT_ERROR;
		} else {
			DBG("TLS, imported %i system certificates", ret);
		}
	}

	// Import provided certificate files.
	ptrnode_t *n;
	WALK_LIST(n, ctx->params->ca_files) {
		const char *file = (char *)n->d;
		ret = gnutls_certificate_set_x509_trust_file(ctx->credentials, file,
		                                             GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			WARN("TLS, failed to import certificate file '%s' (%s)",
			    file, gnutls_strerror_name(ret));
			return KNOT_ERROR;
		} else {
			DBG("TLS, imported %i certificates from '%s'", ret, file);
		}
	}

	gnutls_certificate_set_verify_function(ctx->credentials, verify_certificate);

	// Setup client keypair if specified. Both key and cert files must be provided.
	if (params->keyfile != NULL && params->certfile != NULL) {
		// First, try PEM.
		ret = gnutls_certificate_set_x509_key_file(ctx->credentials,
			params->certfile, params->keyfile, GNUTLS_X509_FMT_PEM);
		if (ret != GNUTLS_E_SUCCESS) {
			// If PEM didn't work, try DER.
			ret = gnutls_certificate_set_x509_key_file(ctx->credentials,
				params->certfile, params->keyfile, GNUTLS_X509_FMT_DER);
		}

		if (ret != GNUTLS_E_SUCCESS) {
			WARN("TLS, failed to add client certfile '%s' and keyfile '%s'",
			     params->certfile, params->keyfile);
			return KNOT_ERROR;
		} else {
			DBG("TLS, added client certfile '%s' and keyfile '%s'",
			    params->certfile, params->keyfile);
		}
	} else if (params->keyfile != NULL) {
		WARN("TLS, cannot use client keyfile without a certfile");
		return KNOT_ERROR;
	} else if (params->certfile != NULL) {
		WARN("TLS, cannot use client certfile without a keyfile");
		return KNOT_ERROR;
	}

	ret = gnutls_init(&ctx->session, GNUTLS_CLIENT | flags);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	ret = gnutls_credentials_set(ctx->session, GNUTLS_CRD_CERTIFICATE,
	                             ctx->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_deinit(ctx->session);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int tls_ctx_setup_remote_endpoint(tls_ctx_t *ctx, const gnutls_datum_t *alpn,
        size_t alpn_size, const char *priority, const char *remote)
{
	if (ctx == NULL || ctx->session == NULL || ctx->credentials == NULL) {
		return KNOT_EINVAL;
	}
	int ret = 0;
	if (alpn != NULL) {
		ret = gnutls_alpn_set_protocols(ctx->session, alpn, alpn_size, 0);
		if (ret != GNUTLS_E_SUCCESS) {
			gnutls_deinit(ctx->session);
			return KNOT_NET_ECONNECT;
		}
	}

	if (priority != NULL) {
		ret = gnutls_priority_set_direct(ctx->session, priority, NULL);
	} else {
		ret = gnutls_set_default_priority(ctx->session);
	}
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_deinit(ctx->session);
		return KNOT_EINVAL;
	}

	if (remote != NULL) {
		ret = gnutls_server_name_set(ctx->session, GNUTLS_NAME_DNS, remote,
		                             strlen(remote));
		if (ret != GNUTLS_E_SUCCESS) {
			gnutls_deinit(ctx->session);
			return KNOT_EINVAL;
		}
	}
	return KNOT_EOK;
}

int tls_ctx_connect(tls_ctx_t *ctx, int sockfd, bool fastopen,
        struct sockaddr_storage *addr)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int ret = 0;
	gnutls_session_set_ptr(ctx->session, ctx);

	if (fastopen) {
#if GNUTLS_VERSION_NUMBER >= GNUTLS_VERSION_FASTOPEN_READY
		gnutls_transport_set_fastopen(ctx->session, sockfd, (struct sockaddr *)addr,
		                              sockaddr_len(addr), 0);
#else
		gnutls_deinit(ctx->session);
		return KNOT_ENOTSUP;
#endif
	} else {
		gnutls_transport_set_int(ctx->session, sockfd);
	}

	gnutls_handshake_set_timeout(ctx->session, 1000 * ctx->wait);

	// Initialize poll descriptor structure.
	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	// Perform the TLS handshake
	do {
		ret = gnutls_handshake(ctx->session);
		if (ret != GNUTLS_E_SUCCESS && gnutls_error_is_fatal(ret) == 0) {
			if (poll(&pfd, 1, 1000 * ctx->wait) != 1) {
				WARN("TLS, peer took too long to respond");
				gnutls_deinit(ctx->session);
				return KNOT_NET_ETIMEOUT;
			}
		}
	} while (ret != GNUTLS_E_SUCCESS && gnutls_error_is_fatal(ret) == 0);
	if (ret != GNUTLS_E_SUCCESS) {
		WARN("TLS, handshake failed (%s)", gnutls_strerror(ret));
		tls_ctx_close(ctx);
		return KNOT_NET_ESOCKET;
	}

	// Save the socket descriptor.
	ctx->sockfd = sockfd;

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
		WARN("TLS, failed to send");
		return KNOT_NET_ESEND;
	}
	if (gnutls_record_send(ctx->session, buf, buf_len) <= 0) {
		WARN("TLS, failed to send");
		return KNOT_NET_ESEND;
	}

	while (gnutls_record_check_corked(ctx->session) > 0) {
		int ret = gnutls_record_uncork(ctx->session, 0);
		if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
			WARN("TLS, failed to send (%s)", gnutls_strerror(ret));
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

	// Initialize poll descriptor structure.
	struct pollfd pfd = {
		.fd = ctx->sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	uint32_t total = 0;
	uint16_t msg_len = 0;

	// Receive message header.
	while (total < sizeof(msg_len)) {
		ssize_t ret = gnutls_record_recv(ctx->session,
		                                 (uint8_t *)&msg_len + total,
		                                 sizeof(msg_len) - total);
		if (ret > 0) {
			total += ret;
		} else if (ret == 0) {
			WARN("TLS, peer has closed the connection");
			return KNOT_NET_ERECV;
		} else if (gnutls_error_is_fatal(ret) != 0) {
			WARN("TLS, failed to receive reply (%s)",
			     gnutls_strerror(ret));
			return KNOT_NET_ERECV;
		} else if (poll(&pfd, 1, 1000 * ctx->wait) != 1) {
			WARN("TLS, peer took too long to respond");
			return KNOT_NET_ETIMEOUT;
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
			WARN("TLS, peer has closed the connection");
			return KNOT_NET_ERECV;
		} else if (gnutls_error_is_fatal(ret) != 0) {
			WARN("TLS, failed to receive reply (%s)",
			     gnutls_strerror(ret));
			return KNOT_NET_ERECV;
		} else if (poll(&pfd, 1, 1000 * ctx->wait) != 1) {
			WARN("TLS, peer took too long to respond");
			return KNOT_NET_ETIMEOUT;
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

	if (ctx->credentials != NULL) {
		gnutls_certificate_free_credentials(ctx->credentials);
		ctx->credentials = NULL;
	}
	if (ctx->session != NULL) {
		gnutls_deinit(ctx->session);
		ctx->session = NULL;
	}
}

void print_tls(const tls_ctx_t *ctx)
{
	if (ctx == NULL || ctx->params == NULL || !ctx->params->enable || ctx->session == NULL) {
		return;
	}

	char *msg = gnutls_session_get_desc(ctx->session);
	printf(";; TLS session %s\n", msg);
	gnutls_free(msg);
}
