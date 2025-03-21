/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup rrtype
 * @{
 */

#pragma once

#include <stdint.h>

/*!
 * \brief Counts the size of the NAPTR RDATA before the Replacement domain name.
 *
 * See RFC 2915.
 *
 * \param naptr  Wire format of NAPTR record.
 * \param maxp   Limit of the wire format.
 *
 * \retval KNOT_EMALF if the record is malformed.
 * \retval Size of the RDATA before the Replacement domain name.
 */
int knot_naptr_header_size(const uint8_t *naptr, const uint8_t *maxp);

/*! @} */
