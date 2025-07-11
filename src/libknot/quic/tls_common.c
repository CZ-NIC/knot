/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <fcntl.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/x509-ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "libknot/quic/tls_common.h"

#include "contrib/atomic.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "libknot/attribute.h"
#include "libknot/error.h"

typedef struct knot_creds {
	knot_atomic_ptr_t cert_creds; // Current credentials.
	uint64_t creds_hash; // Hashed creds sources to detect changes.
	gnutls_certificate_credentials_t cert_creds_prev; // Previous credentials (for pending connections).
	gnutls_anti_replay_t tls_anti_replay;
	gnutls_datum_t tls_ticket_key;
	bool peer;
	const char *peer_hostnames[KNOT_TLS_MAX_PINS + 1];
	const uint8_t *peer_pins[KNOT_TLS_MAX_PINS + 1];
} knot_creds_t;

_public_
const char *knot_tls_priority(bool tls12)
{
#if GNUTLS_VERSION_NUMBER >= 0x030702
#define TLS_COMPAT      "%DISABLE_TLS13_COMPAT_MODE:"
#else
#define TLS_COMPAT      ""
#endif

#define COMMON_PRIORITY "-VERS-ALL:+VERS-TLS1.3:" \
                        TLS_COMPAT \
                        "-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:" \
                                   "+GROUP-SECP384R1:+GROUP-SECP521R1"
#define TLS12           ":+VERS-TLS1.2"

	return tls12 ? COMMON_PRIORITY TLS12 : COMMON_PRIORITY;
}

static int tls_anti_replay_db_add_func(void *dbf, time_t exp_time,
                                       const gnutls_datum_t *key,
                                       const gnutls_datum_t *data)
{
	return 0;
}

static void tls_session_ticket_key_free(gnutls_datum_t *ticket)
{
	memzero(ticket->data, ticket->size);
	gnutls_free(ticket->data);
}

static int self_key(gnutls_x509_privkey_t *privkey, const char *key_file, int uid, int gid)
{
	gnutls_datum_t data = { 0 };

	int ret = gnutls_x509_privkey_init(privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		return ret;
	}

	int fd = open(key_file, O_RDONLY);
	if (fd != -1) {
		struct stat stat;
		if (fstat(fd, &stat) != 0 ||
		    (data.data = gnutls_malloc(stat.st_size)) == NULL ||
		    read(fd, data.data, stat.st_size) != stat.st_size) {
			ret = GNUTLS_E_KEYFILE_ERROR;
			goto finish;
		}

		data.size = stat.st_size;
		ret = gnutls_x509_privkey_import_pkcs8(*privkey, &data, GNUTLS_X509_FMT_PEM,
		                                       NULL, GNUTLS_PKCS_PLAIN);
		if (ret != GNUTLS_E_SUCCESS) {
			goto finish;
		}
	} else {
		ret = gnutls_x509_privkey_generate(*privkey, GNUTLS_PK_EDDSA_ED25519,
		                                   GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_ED25519), 0);
		if (ret != GNUTLS_E_SUCCESS) {
			goto finish;
		}

		ret = gnutls_x509_privkey_export2_pkcs8(*privkey, GNUTLS_X509_FMT_PEM, NULL,
		                                        GNUTLS_PKCS_PLAIN, &data);
		if (ret != GNUTLS_E_SUCCESS ||
		    (fd = open(key_file, O_WRONLY | O_CREAT, 0600)) == -1 ||
		    fchown(fd, uid, gid) < 0 ||
		    write(fd, data.data, data.size) != data.size) {
			ret = GNUTLS_E_KEYFILE_ERROR;
			goto finish;
		}
	}

finish:
	if (fd > -1) {
		close(fd);
	}
	gnutls_free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(*privkey);
		*privkey = NULL;
	}
	return ret;
}

static int self_signed_cert(gnutls_certificate_credentials_t tls_cert,
                            const char *key_file, int uid, int gid)
{
	gnutls_x509_privkey_t privkey = NULL;
	gnutls_x509_crt_t cert = NULL;
	gnutls_subject_alt_names_t san = NULL;
	gnutls_datum_t san_der = { 0 };

	gnutls_datum_t hostname = {
		.data = (unsigned char *)sockaddr_hostname()
	};
	if (hostname.data == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}
	hostname.size = strlen((char *)hostname.data);

	int ret;
	uint8_t serial[16];
	gnutls_rnd(GNUTLS_RND_NONCE, serial, sizeof(serial));
	// Clear the left-most bit to be a positive number (two's complement form).
	serial[0] &= 0x7F;

#define CHK(cmd) if ((ret = (cmd)) != GNUTLS_E_SUCCESS) { goto finish; }
#define NOW_DAYS(days) (time(NULL) + 24 * 3600 * (days))

	CHK(self_key(&privkey, key_file, uid, gid));

	CHK(gnutls_x509_crt_init(&cert));
	CHK(gnutls_x509_crt_set_version(cert, 3));
	CHK(gnutls_x509_crt_set_serial(cert, serial, sizeof(serial)));
	CHK(gnutls_x509_crt_set_activation_time(cert, NOW_DAYS(-1)));
	CHK(gnutls_x509_crt_set_expiration_time(cert, NOW_DAYS(10 * 365)));
	CHK(gnutls_x509_crt_set_issuer_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME,
	                                         0, hostname.data, hostname.size));

	CHK(gnutls_subject_alt_names_init(&san));
	CHK(gnutls_subject_alt_names_set(san, GNUTLS_SAN_DNSNAME, &hostname, 0));
	CHK(gnutls_x509_ext_export_subject_alt_names(san, &san_der));
	CHK(gnutls_x509_crt_set_extension_by_oid(cert, GNUTLS_X509EXT_OID_SAN,
	                                         san_der.data, san_der.size, 1));

	CHK(gnutls_x509_crt_set_key(cert, privkey));
	CHK(gnutls_x509_crt_sign2(cert, cert, privkey, GNUTLS_DIG_SHA512, 0));

	ret = gnutls_certificate_set_x509_key(tls_cert, &cert, 1, privkey);

finish:
	free(hostname.data);
	gnutls_free(san_der.data);
	gnutls_x509_crt_deinit(cert);
	gnutls_x509_privkey_deinit(privkey);
	gnutls_subject_alt_names_deinit(san);

	return ret;
}

_public_
int knot_creds_init(struct knot_creds **out,
                    const char *key_file,
                    const char *cert_file,
                    const char **ca_files,
                    bool system_ca,
                    int uid,
                    int gid)
{
	if (out == NULL) {
		return KNOT_EINVAL;
	}

	knot_creds_t *creds = calloc(1, sizeof(*creds));
	if (creds == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = knot_creds_update(creds, key_file, cert_file, ca_files, system_ca, uid, gid);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	if (gnutls_anti_replay_init(&creds->tls_anti_replay) != GNUTLS_E_SUCCESS) {
		ret = KNOT_ENOMEM;
		goto fail;
	}
	gnutls_anti_replay_set_add_function(creds->tls_anti_replay, tls_anti_replay_db_add_func);
	gnutls_anti_replay_set_ptr(creds->tls_anti_replay, NULL);

	if (gnutls_session_ticket_key_generate(&creds->tls_ticket_key) != GNUTLS_E_SUCCESS) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	*out = creds;
	return KNOT_EOK;
fail:
	knot_creds_free(creds);
	return ret;
}

_public_
struct knot_creds *knot_creds_init_peer(const struct knot_creds *local_creds,
                                        const char *const peer_hostnames[KNOT_TLS_MAX_PINS],
                                        const uint8_t *const peer_pins[KNOT_TLS_MAX_PINS])
{
	knot_creds_t *creds = calloc(1, sizeof(*creds));
	if (creds == NULL) {
		return NULL;
	}

	if (local_creds != NULL) {
		creds->peer = true;
		ATOMIC_INIT(creds->cert_creds, ATOMIC_GET(local_creds->cert_creds));
	} else {
		gnutls_certificate_credentials_t new_creds;
		int ret = gnutls_certificate_allocate_credentials(&new_creds);
		if (ret != GNUTLS_E_SUCCESS) {
			free(creds);
			return NULL;
		}
		ATOMIC_INIT(creds->cert_creds, new_creds);
	}

	if (peer_pins != NULL) {
		memcpy(creds->peer_pins, peer_pins,
		       sizeof(peer_pins[0]) * KNOT_TLS_MAX_PINS);
	}
	if (peer_hostnames != NULL) {
		memcpy(creds->peer_hostnames, peer_hostnames,
		       sizeof(peer_hostnames[0]) * KNOT_TLS_MAX_PINS);
	}

	return creds;
}

static int creds_cert(gnutls_certificate_credentials_t creds,
                      struct gnutls_x509_crt_int **cert)
{
	gnutls_x509_crt_t *certs;
	unsigned cert_count;
	int ret = gnutls_certificate_get_x509_crt(creds, 0, &certs, &cert_count);
	if (ret == GNUTLS_E_SUCCESS) {
		if (cert_count == 0) {
			gnutls_x509_crt_deinit(*certs);
			return KNOT_ENOENT;
		}
		*cert = *certs;
		free(certs);
		return KNOT_EOK;
	}
	return KNOT_ERROR;
}

static void hash_file(SIPHASH_CTX *ctx, const char *file_name)
{
	assert(ctx);
	assert(file_name);

	char *data;
	struct stat file_stat;
	int fd = open(file_name, O_RDONLY);
	if (fd == -1 ||
	    fstat(fd, &file_stat) == -1 ||
	    (data = mmap(0, file_stat.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		if (fd > -1) {
			close(fd);
		}
		return;
	}

	SipHash24_Update(ctx, data, file_stat.st_size);

	munmap(data, file_stat.st_size);
	close(fd);
}

static uint64_t creds_hash(const char *key_file,
                           const char *cert_file,
                           const char **ca_files,
                           bool system_ca)
{
	SIPHASH_CTX ctx;
	SIPHASH_KEY key = { 0 };
	SipHash24_Init(&ctx, &key);

	assert(key_file);
	hash_file(&ctx, key_file);
	if (cert_file != NULL) {
		hash_file(&ctx, cert_file);
	}
	if (ca_files != NULL) {
		for (const char **file = ca_files; *file != NULL; file++) {
			hash_file(&ctx, *file);
		}
	}
	if (system_ca) {
		SipHash24_Update(&ctx, "\x01", 1);
	}

	return SipHash24_End(&ctx);
}

_public_
int knot_creds_update(struct knot_creds *creds,
                      const char *key_file,
                      const char *cert_file,
                      const char **ca_files,
                      bool system_ca,
                      int uid,
                      int gid)
{
	if (creds == NULL || key_file == NULL) {
		return KNOT_EINVAL;
	}

	uint64_t new_hash = creds_hash(key_file, cert_file, ca_files, system_ca);
	if (creds->creds_hash == new_hash) {
		return KNOT_EOK;
	}

	gnutls_certificate_credentials_t new_creds;
	int ret = gnutls_certificate_allocate_credentials(&new_creds);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	if (cert_file != NULL) {
		ret = gnutls_certificate_set_x509_key_file(new_creds,
		                                           cert_file, key_file,
		                                           GNUTLS_X509_FMT_PEM);
	} else {
		ret = self_signed_cert(new_creds, key_file, uid, gid);
	}
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_certificate_free_credentials(new_creds);
		return KNOT_EFILE;
	}

	if (system_ca) {
		if (gnutls_certificate_set_x509_system_trust(new_creds) < 0) {
			gnutls_certificate_free_credentials(new_creds);
			return KNOT_EBADCERT;
		}
	}
	if (ca_files != NULL) {
		for (const char **file = ca_files; *file != NULL; file++) {
			if (gnutls_certificate_set_x509_trust_file(new_creds, *file,
			                                           GNUTLS_X509_FMT_PEM) < 0) {
				gnutls_certificate_free_credentials(new_creds);
				return KNOT_EBADCERT;
			}
		}
	}

	if (creds->cert_creds_prev != NULL) {
		gnutls_certificate_free_credentials(creds->cert_creds_prev);
	}
	creds->cert_creds_prev = ATOMIC_XCHG(creds->cert_creds, new_creds);
	creds->creds_hash = new_hash;

	return KNOT_EOK;
}

_public_
int knot_creds_cert(struct knot_creds *creds, struct gnutls_x509_crt_int **cert)
{
	if (creds == NULL || cert == NULL) {
		return KNOT_EINVAL;
	}

	return creds_cert(ATOMIC_GET(creds->cert_creds), cert);
}

_public_
void knot_creds_free(struct knot_creds *creds)
{
	if (creds == NULL) {
		return;
	}

	if (!creds->peer && ATOMIC_GET(creds->cert_creds) != NULL) {
		gnutls_certificate_free_credentials(ATOMIC_GET(creds->cert_creds));
		ATOMIC_DEINIT(creds->cert_creds);
		if (creds->cert_creds_prev != NULL) {
			gnutls_certificate_free_credentials(creds->cert_creds_prev);
		}
	}
	gnutls_anti_replay_deinit(creds->tls_anti_replay);
	if (creds->tls_ticket_key.data != NULL) {
		tls_session_ticket_key_free(&creds->tls_ticket_key);
	}
	free(creds);
}

_public_
int knot_tls_session(struct gnutls_session_int **session,
                     struct knot_creds *creds,
                     struct gnutls_priority_st *priority,
                     knot_tls_flag_t flags)
{
	if (session == NULL || creds == NULL || priority == NULL) {
		return KNOT_EINVAL;
	}

	bool server = flags & KNOT_TLS_SERVER;
	bool quic = flags & KNOT_TLS_QUIC;
	bool early_data = flags & KNOT_TLS_EARLY_DATA;

	const char *alpn = NULL;
	if (flags & KNOT_TLS_DNS) {
		alpn = quic ? "\x03""doq" : "\x03""dot";
	}

	gnutls_init_flags_t tls_flags = GNUTLS_NO_SIGNAL;
	if (early_data) {
		tls_flags |= GNUTLS_ENABLE_EARLY_DATA;
#ifdef ENABLE_QUIC // Next flags aren't available in older GnuTLS versions.
		if (quic) {
			tls_flags |= GNUTLS_NO_END_OF_EARLY_DATA;
		}
#endif
	}

	int ret = gnutls_init(session, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) | tls_flags);
	if (ret == GNUTLS_E_SUCCESS) {
		gnutls_certificate_send_x509_rdn_sequence(*session, 1);
		gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUEST);
		ret = gnutls_priority_set(*session, priority);
	}
	if (server && ret == GNUTLS_E_SUCCESS) {
		ret = gnutls_session_ticket_enable_server(*session, &creds->tls_ticket_key);
	}
	if (ret == GNUTLS_E_SUCCESS) {
		if (alpn != NULL) {
			const gnutls_datum_t alpn_datum = { (void *)&alpn[1], alpn[0] };
			gnutls_alpn_set_protocols(*session, &alpn_datum, 1, GNUTLS_ALPN_MANDATORY);
		}
		if (early_data) {
			gnutls_record_set_max_early_data_size(*session, 0xffffffffu);
		}
		if (server) {
			gnutls_anti_replay_enable(*session, creds->tls_anti_replay);
		}
		ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE,
		                             ATOMIC_GET(creds->cert_creds));
	}
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_deinit(*session);
		*session = NULL;
	}
	return ret == GNUTLS_E_SUCCESS ? KNOT_EOK : KNOT_ERROR;
}

_public_
void knot_tls_pin(struct gnutls_session_int *session, uint8_t *pin,
                  size_t *pin_size, bool local)
{
	if (session == NULL) {
		goto error;
	}

	const gnutls_datum_t *data = NULL;
	if (local) {
		data = gnutls_certificate_get_ours(session);
	} else {
		unsigned count = 0;
		data = gnutls_certificate_get_peers(session, &count);
		if (count == 0) {
			goto error;
		}
	}
	if (data == NULL) {
		goto error;
	}

	gnutls_x509_crt_t cert;
	int ret = gnutls_x509_crt_init(&cert);
	if (ret != GNUTLS_E_SUCCESS) {
		goto error;
	}

	ret = gnutls_x509_crt_import(cert, data, GNUTLS_X509_FMT_DER);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(cert);
		goto error;
	}

	ret = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, pin, pin_size);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(cert);
		goto error;
	}

	gnutls_x509_crt_deinit(cert);

	return;
error:
	if (pin_size != NULL) {
		*pin_size = 0;
	}
}

_public_
int knot_tls_pin_check(struct gnutls_session_int *session,
                       struct knot_creds *creds)
{
	// if no pin set -> opportunistic mode
	if (creds->peer_pins[0] == NULL) {
		return KNOT_EOK;
	}

	uint8_t pin[KNOT_TLS_PIN_LEN];
	size_t pin_size = sizeof(pin);
	knot_tls_pin(session, pin, &pin_size, false);
	if (pin_size != KNOT_TLS_PIN_LEN) {
		return KNOT_EBADCERT;
	}

	for (const uint8_t **it = creds->peer_pins; *it != NULL; it++) {
		if (const_time_memcmp(pin, *it, KNOT_TLS_PIN_LEN) == 0) {
			return KNOT_EOK;
		}
	}

	return KNOT_EBADCERT;
}

_public_
int knot_tls_cert_check_hostnames(struct gnutls_session_int *session,
                                  const char *hostnames[])
{
	// if no hostname set -> opportunistic mode
	if (hostnames == NULL || hostnames[0] == NULL) {
		return KNOT_EOK;
	}

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		return KNOT_EBADCERT;
	}

	unsigned status = 0;
	int ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret != GNUTLS_E_SUCCESS || status != 0) {
		return KNOT_EBADCERT;
	}

	unsigned count = 0;
	const gnutls_datum_t *cert_list = gnutls_certificate_get_peers(session, &count);
	if (count == 0) {
		return KNOT_EBADCERT;
	}

	gnutls_x509_crt_t cert;
	ret = gnutls_x509_crt_init(&cert);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_EBADCERT;
	}

	// standard compliant servers send an ordered cert list, so the 0th cert is peer's
	ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(cert);
		return KNOT_EBADCERT;
	}

	// using gnutls_x509_crt_check_hostname() to enforce SAN-only hostname checking
	// see https://datatracker.ietf.org/doc/html/rfc8310#section-8.1
	for (const char **hostname = hostnames; *hostname != NULL; hostname++) {
		if (gnutls_x509_crt_check_hostname(cert, *hostname)) {
			gnutls_x509_crt_deinit(cert);
			return KNOT_EOK;
		}
	}

	gnutls_x509_crt_deinit(cert);

	return KNOT_EBADCERT;
}

_public_
int knot_tls_cert_check(struct gnutls_session_int *session,
                        struct knot_creds *creds)
{
	return knot_tls_cert_check_hostnames(session, creds->peer_hostnames);
}

_public_
uint64_t knot_creds_hash(struct knot_creds *creds)
{
	return creds->creds_hash;
}
