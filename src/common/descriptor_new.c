/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "common/descriptor_new.h"

/*!
 * \brief RR type descriptors.
 */
static const rdata_descriptor_t rdata_descriptors[] = {
	[0]			 = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_A]          = { { 4, KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_NS]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_CNAME]      = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_SOA]        = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_COMPRESSED_DNAME,
				       20, KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_PTR]        = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_HINFO]      = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_MINFO]      = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_MX]         = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_TXT]        = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_RP]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_AFSDB]      = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_RT]         = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_KEY]        = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_AAAA]       = { { 16, KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_LOC]        = { { 16, KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_SRV]        = { { 6, KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_NAPTR]      = { { KNOT_RDATA_WF_NAPTR_HEADER,
				       KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_KX]         = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_CERT]       = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_DNAME]      = { { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_OPT]        = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_APL]        = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_DS]         = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_SSHFP]      = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_IPSECKEY]   = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_RRSIG]      = { { 20, KNOT_RDATA_WF_LITERAL_DNAME,
				       KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_NSEC]       = { { KNOT_RDATA_WF_LITERAL_DNAME,
				       KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_DNSKEY]     = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_DHCID]      = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_NSEC3]      = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_NSEC3PARAM] = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_TLSA]       = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_SPF]        = { { KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
	[KNOT_RRTYPE_TSIG]       = { { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
				       KNOT_RDATA_WF_REMAINDER,
				       KNOT_RDATA_WF_END } },
};

const rdata_descriptor_t *get_rdata_descriptor(const uint16_t type)
{
	if (type <= KNOT_RRTYPE_TSIG) {
		return &rdata_descriptors[type];
	} else {
		return &rdata_descriptors[0];
	}
}

