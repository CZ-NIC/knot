/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup keytag
 *
 * \brief Low-level key tag computation API.
 *
 * The module provides simple interface for DNSKEY key id computation.
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include "libknot/dnssec/binary.h"

/*!
 * Compute a key tag for a DNSSEC key.
 *
 * \param[in]  rdata   DNSKEY RDATA.
 * \param[out] keytag  Computed keytag.
 *
 * \return Error code, KNOT_EOK of successful.
 */
int dnssec_keytag(const dnssec_binary_t *rdata, uint16_t *keytag);

/*! @} */
