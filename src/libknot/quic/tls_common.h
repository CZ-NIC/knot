/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Credentials handling common to QUIC and TLS.
 *
 * \addtogroup quic
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "contrib/ucw/lists.h"

#define KNOT_TLS_PIN_LEN    32

struct gnutls_priority_st;
struct gnutls_session_int;
struct gnutls_x509_crt_int;
struct knot_creds;
struct knot_tls_session;

typedef enum {
	KNOT_TLS_CLIENT     = 0,
	KNOT_TLS_SERVER     = (1 << 0),
	KNOT_TLS_QUIC       = (1 << 1),
	KNOT_TLS_DNS        = (1 << 2),
	KNOT_TLS_EARLY_DATA = (1 << 3),
} knot_tls_flag_t;

/*!
 * \brief Get priority string for GnuTLS priority initialization.
 *
 * \param tls12         Allow TLS 1.2.
 *
 * \return Priority string.
 */
const char *knot_tls_priority(bool tls12);

/*!
 * \brief Init server TLS key and certificate for DoQ.
 *
 * \param key_file      Key PEM file path/name.
 * \param cert_file     X509 certificate PEM file path/name (NULL if auto-generated).
 * \param ca_files      Which additional certificate indicators to import.
 * \param system_ca     Whether to import system certificate indicators.
 * \param uid           Generated key file owner id.
 * \param gid           Generated key file group id.
 * \param err[out]      Output parameter for knot error code.
 *
 * \return Initialized creds.
 */
struct knot_creds *knot_creds_init(const char *key_file,
				   const char *cert_file,
				   const list_t *ca_files,
				   bool system_ca,
				   int uid,
				   int gid,
				   int *err);

/*!
 * \brief Init peer TLS key and certificate for DoQ.
 *
 * \param local_creds   Local credentials if server.
 * \param peer_hostname Peer hostname to be checked against cert. NULL to disable check.
 * \param peer_pin      Optional peer certificate pin to check.
 * \param peer_pin_len  Length of the peer pin. Set 0 if not specified.
 *
 * \return Initialized creds.
 */
struct knot_creds *knot_creds_init_peer(const struct knot_creds *local_creds,
					const char *peer_hostname,
                                        const uint8_t *peer_pin,
                                        uint8_t peer_pin_len);

/*!
 * \brief Load new server TLS key and certificate for DoQ.
 *
 * \param creds         Server credentials where key/cert pair will be updated.
 * \param key_file      Key PEM file path/name.
 * \param cert_file     X509 certificate PEM file path/name (NULL if auto-generated).
 * \param ca_files      Which additional certificate indicators to import.
 * \param system_ca     Whether to import system certificate indicators.
 * \param uid           Generated key file owner id.
 * \param gid           Generated key file group id.
 *
 * \return KNOT_E*
 */
int knot_creds_update(struct knot_creds *creds,
		      const char *key_file,
		      const char *cert_file,
		      const list_t *ca_files,
		      bool system_ca,
		      int uid,
		      int gid);

/*!
 * \brief Gets the certificate from credentials.
 *
 * \param creds  TLS credentials.
 * \param cert   Output certificate.
 *
 * \return KNOT_E*
 */
int knot_creds_cert(struct knot_creds *creds, struct gnutls_x509_crt_int **cert);

/*!
 * \brief Deinit server TLS certificate for DoQ.
 */
void knot_creds_free(struct knot_creds *creds);

/*!
 * \brief Initialize GnuTLS session with credentials, ALPN, etc.
 *
 * \param session      Out: initialized GnuTLS session struct.
 * \param creds        Certificate credentials.
 * \param priority     Session priority configuration.
 * \param flags        TLS-related flags.
 *
 * \return KNOT_E*
 */
int knot_tls_session(struct gnutls_session_int **session,
                     struct knot_creds *creds,
                     struct gnutls_priority_st *priority,
                     knot_tls_flag_t flags);

/*!
 * \brief Gets local or remote certificate pin.
 *
 * \note Zero output pin_size value means no certificate available or error.
 *
 * \param session   TLS connection.
 * \param pin       Output certificate pin.
 * \param pin_size  Input size of the storage / output size of the stored pin.
 * \param local     Local or remote certificate indication.
 */
void knot_tls_pin(struct gnutls_session_int *session, uint8_t *pin,
                  size_t *pin_size, bool local);

/*!
 * \brief Checks remote certificate pin in the session against credentials.
 *
 * \param session   TLS connection.
 * \param creds     TLS credentials.
 *
 * \return KNOT_EOK or KNOT_EBADCERT
 */
int knot_tls_pin_check(struct gnutls_session_int *session,
                       struct knot_creds *creds);

/*!
 * \brief Checks remote certificate validity against credentials.
 *
 * \param session   TLS connection.
 * \param nhostname Number of possible hostnames in hostname array.
 * \param hostname  Array of possible hostnames.
 *
 * \return KNOT_EOK or KNOT_EBADCERT
 */
int knot_tls_cert_check(struct gnutls_session_int *session,
			unsigned nhostnames,
                        const char *hostnames[static nhostnames]);

/*!
 * \brief Checks remote certificate validity against credentials.
 *
 * \param session   TLS connection.
 * \param creds     TLS credentials.
 *
 * \return KNOT_EOK or KNOT_EBADCERT
 */
int knot_tls_cert_check_creds(struct gnutls_session_int *session,
                              struct knot_creds *creds);

/*! @} */
