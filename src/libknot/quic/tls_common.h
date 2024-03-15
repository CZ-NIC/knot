/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KNOT_TLS_PIN_LEN	32

struct gnutls_session_int;
struct gnutls_x509_crt_int;
struct knot_quic_creds;

/*!
 * \brief Init server TLS certificate for DoQ.
 *
 * \param cert_file     X509 certificate PEM file path/name (NULL if auto-generated).
 * \param key_file      Key PEM file path/name.
 *
 * \return Initialized creds.
 */
struct knot_quic_creds *knot_quic_init_creds(const char *cert_file,
                                             const char *key_file);

/*!
 * \brief Init peer TLS certificate for DoQ.
 *
 * \param local_creds   Local credentials if server.
 * \param peer_pin      Optional peer certificate pin to check.
 * \param peer_pin_len  Length of the peer pin. Set 0 if not specified.
 *
 * \return Initialized creds.
 */
struct knot_quic_creds *knot_quic_init_creds_peer(const struct knot_quic_creds *local_creds,
                                                  const uint8_t *peer_pin,
                                                  uint8_t peer_pin_len);

/*!
 * \brief Gets the certificate from credentials.
 *
 * \param creds  TLS credentials.
 * \param cert   Output certificate.
 *
 * \return KNOT_E*
 */
int knot_quic_creds_cert(struct knot_quic_creds *creds, struct gnutls_x509_crt_int **cert);

/*!
 * \brief Deinit server TLS certificate for DoQ.
 */
void knot_quic_free_creds(struct knot_quic_creds *creds);

/*!
 * \brief Initialize GnuTLS session with credentials, ALPN, etc.
 *
 * \param session      Out: initialized GnuTLS session struct.
 * \param creds        Certificate credentials.
 * \param priority     Session priority configuration.
 * \param alpn         ALPN string, first byte is the string length.
 * \param early_data   Allow early data.
 * \param server       Should be server session (otherwise client).
 *
 * \return KNOT_E*
 */
int knot_tls_session(struct gnutls_session_int **session,
                     struct knot_quic_creds *creds,
                     const char *priority,
                     const char *alpn,
                     bool early_data,
                     bool server);

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
 * \return KNOT_EOK or KNOT_EBADCERTKEY
 */
int knot_tls_pin_check(struct gnutls_session_int *session,
                       struct knot_quic_creds *creds);
