#pragma once

#include <gnutls/abstract.h>

#include "binary.h"
#include "key.h"

/*!
 * Encode public key into the format used in DNSKEY RDATA.
 *
 * \param[in]  key    Public key to be encoded.
 * \param[out] rdata  Encoded key (allocated).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int convert_pubkey_to_dnskey(gnutls_pubkey_t key, dnssec_binary_t *rdata);

/*!
 * Create public key from the format encoded in DNSKEY RDATA.
 *
 * \param[in]  algorithm  DNSSEC algorithm identification.
 * \param[in]  rdata      Public key in DNSKEY RDATA format.
 * \param[out] key        GnuTLS public key (initialized).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int convert_dnskey_to_pubkey(uint8_t algorithm, const dnssec_binary_t *rdata,
			     gnutls_pubkey_t key);
