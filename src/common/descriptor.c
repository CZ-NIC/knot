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

#include <config.h>
#include <stdio.h>			// snprintf
#include <stdlib.h>			// strtoul
#include <strings.h>			// strcasecmp

#include <common/descriptor.h>

/*!
 * \brief Table with DNS classes.
 */
static const char* dns_classes[] = {
	[KNOT_CLASS_IN]   = "IN",
	[KNOT_CLASS_CH]   = "CH",
	[KNOT_CLASS_NONE] = "NONE",
	[KNOT_CLASS_ANY]  = "ANY"
};

/*!
 * \brief RR type descriptors.
 */
static const rdata_descriptor_t rdata_descriptors[] = {
	[0]                      = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, NULL },
	[KNOT_RRTYPE_A]          = { { 4, KNOT_RDATA_WF_END }, "A" },
	[KNOT_RRTYPE_NS]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "NS" },
	[KNOT_RRTYPE_CNAME]      = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "CNAME" },
	[KNOT_RRTYPE_SOA]        = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               20, KNOT_RDATA_WF_END }, "SOA" },
	[KNOT_RRTYPE_PTR]        = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "PTR" },
	[KNOT_RRTYPE_HINFO]      = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "HINFO" },
	[KNOT_RRTYPE_MINFO]      = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "MINFO" },
	[KNOT_RRTYPE_MX]         = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "MX" },
	[KNOT_RRTYPE_TXT]        = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "TXT" },
	[KNOT_RRTYPE_RP]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "RP" },
	[KNOT_RRTYPE_AFSDB]      = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "AFSDB" },
	[KNOT_RRTYPE_RT]         = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "RT" },
	[KNOT_RRTYPE_SIG]        = { { 18, KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "SIG" },
	[KNOT_RRTYPE_KEY]        = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "KEY" },
	[KNOT_RRTYPE_AAAA]       = { { 16, KNOT_RDATA_WF_END }, "AAAA" },
	[KNOT_RRTYPE_LOC]        = { { 16, KNOT_RDATA_WF_END }, "LOC" },
	[KNOT_RRTYPE_SRV]        = { { 6, KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "SRV" },
	[KNOT_RRTYPE_NAPTR]      = { { KNOT_RDATA_WF_NAPTR_HEADER,
	                               KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "NAPTR" },
	[KNOT_RRTYPE_KX]         = { { 2, KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "KX" },
	[KNOT_RRTYPE_CERT]       = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "CERT" },
	[KNOT_RRTYPE_DNAME]      = { { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "DNAME" },
	[KNOT_RRTYPE_OPT]        = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "OPT" },
	[KNOT_RRTYPE_APL]        = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "APL" },
	[KNOT_RRTYPE_DS]         = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "DS" },
	[KNOT_RRTYPE_SSHFP]      = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "SSHFP" },
	[KNOT_RRTYPE_IPSECKEY]   = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "IPSECKEY" },
	[KNOT_RRTYPE_RRSIG]      = { { 18, KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	                               KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "RRSIG" },
	[KNOT_RRTYPE_NSEC]       = { { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	                               KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "NSEC" },
	[KNOT_RRTYPE_DNSKEY]     = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "DNSKEY" },
	[KNOT_RRTYPE_DHCID]      = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "DHCID" },
	[KNOT_RRTYPE_NSEC3]      = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "NSEC3" },
	[KNOT_RRTYPE_NSEC3PARAM] = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "NSEC3PARAM" },
	[KNOT_RRTYPE_TLSA]       = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "TLSA" },
	[KNOT_RRTYPE_SPF]        = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "SPF" },
	[KNOT_RRTYPE_NID]        = { { 10 }, "NID" },
	[KNOT_RRTYPE_L32]        = { { 6 }, "L32" },
	[KNOT_RRTYPE_L64]        = { { 10 }, "L64" },
	[KNOT_RRTYPE_LP]         = { { 2, KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
	                             "LP" },
	[KNOT_RRTYPE_EUI48]      = { { 6, KNOT_RDATA_WF_END }, "EUI48" },
	[KNOT_RRTYPE_EUI64]      = { { 8, KNOT_RDATA_WF_END }, "EUI64" },
	[KNOT_RRTYPE_TKEY]       = { { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	                               KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "TKEY" },
	[KNOT_RRTYPE_TSIG]       = { { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	                               KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "TSIG" },
	[KNOT_RRTYPE_IXFR]       = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "IXFR" },
	[KNOT_RRTYPE_AXFR]       = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "AXFR" },
	[KNOT_RRTYPE_ANY]        = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "ANY" }
};

/*!
 * \brief Some (OBSOLETE) RR type descriptors.
 */
static const rdata_descriptor_t obsolete_rdata_descriptors[] = {
	[0]                      = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, NULL },
	[KNOT_RRTYPE_MD]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "MD" },
	[KNOT_RRTYPE_MF]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "MF" },
	[KNOT_RRTYPE_MB]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "MB" },
	[KNOT_RRTYPE_MG]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "MG" },
	[KNOT_RRTYPE_MR]         = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "MR" },
	[KNOT_RRTYPE_PX]         = { { 2, KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_END }, "PX" },
	[KNOT_RRTYPE_NXT]        = { { KNOT_RDATA_WF_COMPRESSED_DNAME,
	                               KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "NXT" },
};

const rdata_descriptor_t *get_rdata_descriptor(const uint16_t type)
{
	if (type <= KNOT_RRTYPE_ANY &&
	    rdata_descriptors[type].type_name != NULL) {
		return &rdata_descriptors[type];
	} else {
		return &rdata_descriptors[0];
	}
}

const rdata_descriptor_t *get_obsolete_rdata_descriptor(const uint16_t type)
{
	if (type <= KNOT_RRTYPE_NXT &&
	    obsolete_rdata_descriptors[type].type_name != 0) {
		return &obsolete_rdata_descriptors[type];
	} else {
		return &obsolete_rdata_descriptors[0];
	}
}

int knot_rrtype_to_string(const uint16_t rrtype,
                          char           *out,
                          const size_t   out_len)
{
	int ret;

	const rdata_descriptor_t *descr = get_rdata_descriptor(rrtype);

	if (descr->type_name != NULL) {
		ret = snprintf(out, out_len, "%s", descr->type_name);
	} else {
		ret = snprintf(out, out_len, "TYPE%u", rrtype);
	}

	if (ret <= 0 || (size_t)ret >= out_len) {
		return -1;
	} else {
		return ret;
	}
}

int knot_rrtype_from_string(const char *name, uint16_t *num)
{
	int i;
	char *end;
	unsigned long n;

	// Try to find name in descriptors table.
	for (i = 0; i <= KNOT_RRTYPE_ANY; i++) {
		if (rdata_descriptors[i].type_name != NULL &&
		    strcasecmp(rdata_descriptors[i].type_name, name) == 0) {
			*num = i;
			return 0;
		}
	}

	// Type name must begin with TYPE.
	if (strncasecmp(name, "TYPE", 4) != 0) {
		return -1;
	} else {
		name += 4;
	}

	// The rest must be a number.
	n = strtoul(name, &end, 10);
	if (end == name || *end != '\0' || n > UINT16_MAX) {
		return -1;
	}

	*num = n;
	return 0;
}

int knot_rrclass_to_string(const uint16_t rrclass,
                           char           *out,
                           const size_t   out_len)
{
	int ret;

	if (rrclass <= KNOT_CLASS_ANY && dns_classes[rrclass] != NULL) {
		ret = snprintf(out, out_len, "%s", dns_classes[rrclass]);
	} else {
		ret = snprintf(out, out_len, "CLASS%u", rrclass);
	}

	if (ret <= 0 || (size_t)ret >= out_len) {
		return -1;
	} else {
		return ret;
	}
}

int knot_rrclass_from_string(const char *name, uint16_t *num)
{
	int i;
	char *end;
	unsigned long n;

	// Try to find the name in classes table.
	for (i = 0; i <= KNOT_CLASS_ANY; i++) {
		if (dns_classes[i] != NULL &&
		    strcasecmp(dns_classes[i], name) == 0) {
			*num = i;
			return 0;
		}
	}

	// Class name must begin with CLASS.
	if (strncasecmp(name, "CLASS", 5) != 0) {
		return -1;
	} else {
		name += 5;
	}

	// The rest must be a number.
	n = strtoul(name, &end, 10);
	if (end == name || *end != '\0' || n > UINT16_MAX) {
		return -1;
	}

	*num = n;
	return 0;
}

int descriptor_item_is_dname(const int item)
{
	return item == KNOT_RDATA_WF_COMPRESSED_DNAME ||
	       item == KNOT_RDATA_WF_UNCOMPRESSED_DNAME;
}

int descriptor_item_is_compr_dname(const int item)
{
	return item == KNOT_RDATA_WF_COMPRESSED_DNAME;
}

int descriptor_item_is_fixed(const int item)
{
	if (item > 0) {
		return 1;
	} else {
		return 0;
	}
}

int descriptor_item_is_remainder(const int item)
{
	if (item == KNOT_RDATA_WF_REMAINDER) {
		return 1;
	} else {
		return 0;
	}
}

int knot_rrtype_is_metatype(const uint16_t type)
{
	return type == KNOT_RRTYPE_SIG  ||
	       type == KNOT_RRTYPE_OPT  ||
	       type == KNOT_RRTYPE_TKEY ||
	       type == KNOT_RRTYPE_TSIG ||
	       type == KNOT_RRTYPE_IXFR ||
	       type == KNOT_RRTYPE_AXFR ||
	       type == KNOT_RRTYPE_ANY;
}

int knot_rrtype_is_ddns_forbidden(const uint16_t type)
{
	return type == KNOT_RRTYPE_RRSIG      ||
	       type == KNOT_RRTYPE_DNSKEY     ||
	       type == KNOT_RRTYPE_NSEC3PARAM ||
	       type == KNOT_RRTYPE_NSEC       ||
	       type == KNOT_RRTYPE_NSEC3;
}
