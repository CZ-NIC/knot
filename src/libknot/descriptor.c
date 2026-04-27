/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "libknot/attribute.h"
#include "libknot/descriptor.h"
#include "libknot/errcode.h"

/*!
 * \brief Table with supported DNS classes.
 */
static const char* dns_classes[][2] = {
	[KNOT_CLASS_IN]   = { "IN", "INTERNET" },
	[KNOT_CLASS_CH]   = { "CH", "CHAOS" },
	[KNOT_CLASS_NONE] = { "NONE" },
	[KNOT_CLASS_ANY]  = { "ANY" },
};


#define KRW(name) KNOT_RDATA_WF_ ## name
#define DESCRIPTOR_TYPES(XX) \
	XX(A, 4)\
	XX(NS, KRW(COMPRESSIBLE_DNAME))\
	XX(CNAME, KRW(COMPRESSIBLE_DNAME))\
	XX(SOA, KRW(COMPRESSIBLE_DNAME), KRW(COMPRESSIBLE_DNAME), 20)\
	XX(NULL, KRW(REMAINDER_MAYEMPTY))\
	XX(PTR, KRW(COMPRESSIBLE_DNAME))\
	XX(HINFO, KRW(REMAINDER))\
	XX(MINFO, KRW(COMPRESSIBLE_DNAME), KRW(COMPRESSIBLE_DNAME))\
	XX(MX, 2, KRW(COMPRESSIBLE_DNAME))\
	XX(TXT, KRW(REMAINDER))\
	XX(RP, KRW(DECOMPRESSIBLE_DNAME), KRW(DECOMPRESSIBLE_DNAME))\
	XX(AFSDB, 2, KRW(DECOMPRESSIBLE_DNAME))\
	XX(RT, 2, KRW(DECOMPRESSIBLE_DNAME))\
	XX(SIG, 18, KRW(DECOMPRESSIBLE_DNAME), KRW(REMAINDER))\
	XX(KEY, 4, KRW(REMAINDER))\
	XX(AAAA, 16)\
	XX(LOC, 16)\
	XX(SRV, 6, KRW(DECOMPRESSIBLE_DNAME))\
	XX(NAPTR, KRW(NAPTR_HEADER), KRW(DECOMPRESSIBLE_DNAME))\
	XX(KX, 2, KRW(FIXED_DNAME))\
	XX(CERT, 5, KRW(REMAINDER))\
	XX(DNAME, KRW(FIXED_DNAME))\
	XX(OPT, KRW(REMAINDER_MAYEMPTY))\
	XX(APL, KRW(REMAINDER_MAYEMPTY))\
	XX(DS, 4, KRW(REMAINDER))\
	XX(SSHFP, 2, KRW(REMAINDER))\
	XX(IPSECKEY, 3, KRW(REMAINDER))\
	XX(RRSIG, 18, KRW(FIXED_DNAME), KRW(REMAINDER))\
	XX(NSEC, KRW(FIXED_DNAME), KRW(REMAINDER_MAYEMPTY))\
	XX(DNSKEY, 4, KRW(REMAINDER))\
	XX(DHCID, KRW(REMAINDER))\
	XX(NSEC3, 7, KRW(REMAINDER_MAYEMPTY))\
	XX(NSEC3PARAM, 5, KRW(REMAINDER_MAYEMPTY))\
	XX(TLSA, 3, KRW(REMAINDER))\
	XX(SMIMEA, KRW(REMAINDER))\
	XX(CDS, 4, KRW(REMAINDER))\
	XX(CDNSKEY, 4, KRW(REMAINDER))\
	XX(OPENPGPKEY, KRW(REMAINDER))\
	XX(CSYNC, 6, KRW(REMAINDER_MAYEMPTY))\
	XX(ZONEMD, 6, KRW(REMAINDER))\
	XX(SVCB, 2, KRW(FIXED_DNAME), KRW(REMAINDER_MAYEMPTY))\
	XX(HTTPS, 2, KRW(FIXED_DNAME), KRW(REMAINDER_MAYEMPTY))\
	XX(DSYNC, 5, KRW(FIXED_DNAME))\
	XX(SPF, KRW(REMAINDER))\
	XX(NID, 10)\
	XX(L32, 6)\
	XX(L64, 10)\
	XX(LP, 2, KRW(FIXED_DNAME))\
	XX(EUI48, 6)\
	XX(EUI64, 8)\
	XX(NXNAME, KRW(END))/*we doubled the _END but no issue*/\
	XX(TKEY, KRW(FIXED_DNAME), KRW(REMAINDER))\
	XX(TSIG, KRW(FIXED_DNAME), KRW(REMAINDER))\
	XX(IXFR, KRW(REMAINDER_MAYEMPTY))\
	XX(AXFR, KRW(REMAINDER_MAYEMPTY))\
	XX(ANY, KRW(END))/*see NXNAME*/\
	XX(URI, 4, KRW(REMAINDER))\
	XX(CAA, 1, KRW(REMAINDER))\
	XX(RESINFO, KRW(REMAINDER))\
	XX(WALLET, KRW(REMAINDER))\
	XX(ALIAS, KRW(DECOMPRESSIBLE_DNAME))\
	/* the end of the definitions */


/** Array of RR type codes which have a descriptor (which isn't obsolete). */
static const uint16_t described_types[] = {
    #define XX(name, ...) KNOT_RRTYPE_ ## name,
    DESCRIPTOR_TYPES(XX)
    #undef XX
};

_public_
const knot_rdata_descriptor_t *knot_get_rdata_descriptor(const uint16_t type)
{
	/* We define descriptors as individual static variables. */
	#define XX(name, ...) static const knot_rdata_descriptor_t \
		def_ ## name = {{__VA_ARGS__, KRW(END)}, #name};
	DESCRIPTOR_TYPES(XX)
	#undef XX
	/* The default is separate, as we want(?) the name to be NULL. */
	static const knot_rdata_descriptor_t def_default =
		{ { KRW(REMAINDER_MAYEMPTY), KRW(END) }, NULL };

	switch(type) {
		#define XX(name, ...) case KNOT_RRTYPE_ ## name: return &(def_ ## name);
		DESCRIPTOR_TYPES(XX)
		#undef XX
		default: return &def_default;
	}
}

/*!
 * \brief Some (OBSOLETE) RR type descriptors.
 */
static const knot_rdata_descriptor_t obsolete_rdata_descriptors[] = {
	[0]                      = { { KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, NULL },
	[KNOT_RRTYPE_MD]         = { { KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_END }, "MD" },
	[KNOT_RRTYPE_MF]         = { { KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_END }, "MF" },
	[KNOT_RRTYPE_MB]         = { { KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_END }, "MB" },
	[KNOT_RRTYPE_MG]         = { { KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_END }, "MG" },
	[KNOT_RRTYPE_MR]         = { { KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_END }, "MR" },
	[KNOT_RRTYPE_PX]         = { { 2, KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_END }, "PX" },
	[KNOT_RRTYPE_NXT]        = { { KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	                               KNOT_RDATA_WF_REMAINDER,
	                               KNOT_RDATA_WF_END }, "NXT" },
};

_public_
const knot_rdata_descriptor_t *knot_get_obsolete_rdata_descriptor(const uint16_t type)
{
	if (type <= KNOT_RRTYPE_NXT &&
	    obsolete_rdata_descriptors[type].type_name != NULL) {
		return &obsolete_rdata_descriptors[type];
	} else {
		return &obsolete_rdata_descriptors[0];
	}
}

_public_
int knot_rrtype_to_string(const uint16_t rrtype,
                          char           *out,
                          const size_t   out_len)
{
	if (out == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	const knot_rdata_descriptor_t *descr = knot_get_rdata_descriptor(rrtype);

	if (descr->type_name != NULL) {
		ret = snprintf(out, out_len, "%s", descr->type_name);
	} else {
		ret = snprintf(out, out_len, "TYPE%u", rrtype);
	}

	if (ret <= 0 || (size_t)ret >= out_len) {
		return KNOT_ESPACE; // NOTE it is essential to return KNOT_ESPACE when output buffer overflows because this is directly called in rrset_dump and there is a realloc/retry mechanism in KNOT_ESPACE case.
	} else {
		return ret;
	}
}

_public_
int knot_rrtype_from_string(const char *name, uint16_t *num)
{
	if (name == NULL || num == NULL) {
		return KNOT_EINVAL;
	}

	char *end;
	unsigned long n;

	// FIXME: explain?
	for (int i = 0; i < sizeof(described_types) / sizeof(described_types[0]); ++i) {
		uint16_t type = described_types[i];
		if (strcasecmp(name, knot_get_rdata_descriptor(type)->type_name) == 0) {
			*num = type;
			return KNOT_EOK;
		}
	}

	// Type name must begin with TYPE.
	if (strncasecmp(name, "TYPE", 4) != 0) {
		return KNOT_ENOTYPE;
	} else {
		name += 4;
	}

	// The rest must be a number.
	n = strtoul(name, &end, 10);
	if (end == name || *end != '\0' || n > UINT16_MAX) {
		return KNOT_ENOTYPE;
	}

	*num = n;
	return KNOT_EOK;
}

_public_
int knot_rrclass_to_string(const uint16_t rrclass,
                           char           *out,
                           const size_t   out_len)
{
	if (out == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	if (rrclass <= KNOT_CLASS_ANY && dns_classes[rrclass][0] != NULL) {
		ret = snprintf(out, out_len, "%s", dns_classes[rrclass][0]);
	} else {
		ret = snprintf(out, out_len, "CLASS%u", rrclass);
	}

	if (ret <= 0 || (size_t)ret >= out_len) {
		return KNOT_ESPACE;
	} else {
		return ret;
	}
}

_public_
int knot_rrclass_from_string(const char *name, uint16_t *num)
{
	if (name == NULL || num == NULL) {
		return KNOT_EINVAL;
	}

	int i;
	char *end;
	unsigned long n;

	// Try to find the name in classes table.
	for (i = 0; i <= KNOT_CLASS_ANY; i++) {
		const char **row = dns_classes[i];
		if ((row[0] != NULL && strcasecmp(row[0], name) == 0) ||
		    (row[1] != NULL && strcasecmp(row[1], name) == 0)) {
			*num = i;
			return KNOT_EOK;
		}
	}

	// Class name must begin with CLASS.
	if (strncasecmp(name, "CLASS", 5) != 0) {
		return KNOT_ENOCLASS;
	} else {
		name += 5;
	}

	// The rest must be a number.
	n = strtoul(name, &end, 10);
	if (end == name || *end != '\0' || n > UINT16_MAX) {
		return KNOT_ENOCLASS;
	}

	*num = n;
	return KNOT_EOK;
}

_public_
int knot_rrtype_is_metatype(const uint16_t type)
{
	return type == KNOT_RRTYPE_SIG    ||
	       type == KNOT_RRTYPE_OPT    ||
	       type == KNOT_RRTYPE_NXNAME ||
	       type == KNOT_RRTYPE_TKEY   ||
	       type == KNOT_RRTYPE_TSIG   ||
	       type == KNOT_RRTYPE_IXFR   ||
	       type == KNOT_RRTYPE_AXFR   ||
	       type == KNOT_RRTYPE_ANY;
}

_public_
int knot_rrtype_is_dnssec(const uint16_t type)
{
	return type == KNOT_RRTYPE_DNSKEY     ||
	       type == KNOT_RRTYPE_RRSIG      ||
	       type == KNOT_RRTYPE_NSEC       ||
	       type == KNOT_RRTYPE_NSEC3      ||
	       type == KNOT_RRTYPE_NSEC3PARAM ||
	       type == KNOT_RRTYPE_CDNSKEY    ||
	       type == KNOT_RRTYPE_CDS;
}

_public_
int knot_rrtype_additional_needed(const uint16_t type)
{
	return type == KNOT_RRTYPE_NS ||
	       type == KNOT_RRTYPE_MX ||
	       type == KNOT_RRTYPE_SRV ||
	       type == KNOT_RRTYPE_SVCB ||
	       type == KNOT_RRTYPE_HTTPS;
}

_public_
bool knot_rrtype_should_be_lowercased(const uint16_t type)
{
	return type == KNOT_RRTYPE_NS    ||
	       type == KNOT_RRTYPE_MD    ||
	       type == KNOT_RRTYPE_MF    ||
	       type == KNOT_RRTYPE_CNAME ||
	       type == KNOT_RRTYPE_SOA   ||
	       type == KNOT_RRTYPE_MB    ||
	       type == KNOT_RRTYPE_MG    ||
	       type == KNOT_RRTYPE_MR    ||
	       type == KNOT_RRTYPE_PTR   ||
	       type == KNOT_RRTYPE_MINFO ||
	       type == KNOT_RRTYPE_MX    ||
	       type == KNOT_RRTYPE_RP    ||
	       type == KNOT_RRTYPE_AFSDB ||
	       type == KNOT_RRTYPE_RT    ||
	       type == KNOT_RRTYPE_SIG   ||
	       type == KNOT_RRTYPE_PX    ||
	       type == KNOT_RRTYPE_NXT   ||
	       type == KNOT_RRTYPE_NAPTR ||
	       type == KNOT_RRTYPE_KX    ||
	       type == KNOT_RRTYPE_SRV   ||
	       type == KNOT_RRTYPE_DNAME ||
	       type == KNOT_RRTYPE_RRSIG;
}

_public_
bool knot_rrtype_allows_empty(const uint16_t type)
{
	const knot_rdata_descriptor_t *descr = knot_get_rdata_descriptor(type);
	// NOTE obsolete types' descriptors don't have this
	return descr->block_types[0] == KNOT_RDATA_WF_REMAINDER_MAYEMPTY;
}

_public_
int knot_opt_code_to_string(const uint16_t code, char *out, const size_t out_len)
{
	if (out == NULL) {
		return KNOT_EINVAL;
	}

	const char *name = NULL;

	switch (code) {
	case 1:  name = "LLQ"; break;
	case 2:  name = "UL"; break;
	case 3:  name = "NSID"; break;
	case 5:  name = "DAU"; break;
	case 6:  name = "DHU"; break;
	case 7:  name = "N3U"; break;
	case 8:  name = "EDNS-CLIENT-SUBNET"; break;
	case 9:  name = "EDNS-EXPIRE"; break;
	case 10: name = "COOKIE"; break;
	case 11: name = "EDNS-TCP-KEEPALIVE"; break;
	case 12: name = "PADDING"; break;
	case 13: name = "CHAIN"; break;
	case 14: name = "EDNS-KEY-TAG"; break;
	}

	int ret;

	if (name != NULL) {
		ret = snprintf(out, out_len, "%s", name);
	} else {
		ret = snprintf(out, out_len, "CODE%u", code);
	}

	if (ret <= 0 || (size_t)ret >= out_len) {
		return KNOT_ESPACE;
	} else {
		return ret;
	}
}
