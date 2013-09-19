/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdbool.h>
#include <stdint.h>
#include "libknot/dnssec/algorithm.h"

/*!
 * \brief Check if algorithm is supported for zone signing.
 */
bool knot_dnssec_algorithm_is_zonesign(uint8_t algorithm, bool nsec3_enabled)
{
	switch (algorithm) {
	// NSEC only
	case KNOT_DNSSEC_ALG_DSA:
	case KNOT_DNSSEC_ALG_RSASHA1:
		return !nsec3_enabled;

	// NSEC3 only
	case KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1:
	case KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1:
		return true; // allow even with NSEC

	// both NSEC and NSEC3
	case KNOT_DNSSEC_ALG_RSASHA256:
	case KNOT_DNSSEC_ALG_RSASHA512:
	case KNOT_DNSSEC_ALG_ECC_GOST:
	case KNOT_DNSSEC_ALG_ECDSAP256SHA256:
	case KNOT_DNSSEC_ALG_ECDSAP384SHA384:
		return true;

	// unsupported or unknown
	default:
		return false;
	}
}
