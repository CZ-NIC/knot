/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libdnssec/binary.h"

/*
 * The ECDSA signatures in DNSSEC are encoded differently than in X.509
 * (PKCS #1). The cryptographic libraries usually produce the signatures in
 * X.509 format, which uses Dss-Sig-Value to encapsulate 'r' and 's' values
 * of the signature.
 *
 * This module provides decoding and encoding of this format.
 *
 * The 'r' and 's' values are treated as unsigned values: The leading zeroes
 * are stripped on decoding; an extra leading zero is added on encoding in case
 * the value starts with a set bit.
 */

/*!
 * Decode signature parameters from X.509 ECDSA signature.
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
 * Encode signature parameters from X.509 ECDSA signature.
 *
 * \param[in]  s    Value 's' of the signature.
 * \param[in]  r    Value 'r' of the signature.
 * \param[out] der  X.509 signature, the content will be allocated.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dss_sig_value_encode(const dnssec_binary_t *r, const dnssec_binary_t *s,
			 dnssec_binary_t *der);
