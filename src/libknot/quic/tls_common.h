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

#define KNOT_QUIC_PIN_LEN	32

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
