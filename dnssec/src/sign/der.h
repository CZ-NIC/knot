#pragma once

#include "binary.h"

/*
 * The (EC)DSA signatures in DNSSEC are encoded differently than in X.509
 * (PKCS #1). The cryptographic libraries usually produce the signatures in
 * X.509 format, which uses Dss-Sig-Value to encapsulate 'r' and 's' values
 * of the signature.
 *
 * This module provides decoding and encoding of this format.
 */

/*!
 * Decode signature parameters from X.509 (EC)DSA signature.
 *
 * \param[in]  der  X.509 encoded signature.
 * \param[out] s    Value 's' of the signature, will point to the data in DER.
 * \param[out] r    Value 'r' of the signature, will point to the data in DER.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dss_sig_value_decode(const dnssec_binary_t *der,
			 dnssec_binary_t *r, dnssec_binary_t *s);

/*!
 * Encode signature parameters from X.509 (EC)DSA signature.
 *
 * \param[out] der  X.509 signature, the content will be allocated.
 * \param[in]  s    Value 's' of the signature.
 * \param[in]  r    Value 'r' of the signature.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dss_sig_value_encode(dnssec_binary_t *der,
			 const dnssec_binary_t *r, const dnssec_binary_t *s);
