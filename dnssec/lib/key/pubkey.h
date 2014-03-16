#pragma once

#include <gnutls/abstract.h>
#include "binary.h"
#include "key.h"

/*!
 * Convert DNSKEY algorithm identifier to GnuTLS identifier.
 *
 * \param dnssec  DNSSEC DNSKEY algorithm identifier.
 *
 * \return GnuTLS private key algorithm identifier, GNUTLS_PK_UNKNOWN on error.
 */
gnutls_pk_algorithm_t dnskey_algorithm_to_gnutls(dnssec_key_algorithm_t dnssec);

/*!
 * Encode public key to the format used in DNSKEY RDATA.
 *
 * \param key    Public key to be encoded.
 * \param rdata  Encoded key (allocated).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata);

/*!
 * Create public key from the format encoded in DNSKEY RDATA.
 *
 * \param algorithm  DNSSEC algorithm identification.
 * \param rdata      Public key in DNSKEY RDATA format.
 * \param key        Created public key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int rdata_to_pubkey(uint8_t algorithm, const dnssec_binary_t *rdata,
                    gnutls_pubkey_t key);
