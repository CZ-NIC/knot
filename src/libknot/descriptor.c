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

/*!
 * \brief RR type descriptors.
 *
 * \note Variable and <character-string> items are not verified for rdata oversize!
 */
#define KRW(name) KNOT_RDATA_WF_ ## name
#define DESCRIPTOR_TYPES(ITEM) \
	ITEM(A, 4) \
	ITEM(NS, KRW(COMPRESSIBLE_DNAME)) \
	ITEM(CNAME, KRW(COMPRESSIBLE_DNAME)) \
	ITEM(SOA, KRW(COMPRESSIBLE_DNAME), KRW(COMPRESSIBLE_DNAME), 20) \
	ITEM(NULL, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(PTR, KRW(COMPRESSIBLE_DNAME)) \
	ITEM(HINFO, KRW(REMAINDER)) \
	ITEM(MINFO, KRW(COMPRESSIBLE_DNAME), KRW(COMPRESSIBLE_DNAME)) \
	ITEM(MX, 2, KRW(COMPRESSIBLE_DNAME)) \
	ITEM(TXT, KRW(REMAINDER)) \
	ITEM(RP, KRW(DECOMPRESSIBLE_DNAME), KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(AFSDB, 2, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(RT, 2, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(SIG, 18, KRW(DECOMPRESSIBLE_DNAME), KRW(REMAINDER)) \
	ITEM(KEY, 4, KRW(REMAINDER)) \
	ITEM(AAAA, 16) \
	ITEM(LOC, 16) \
	ITEM(SRV, 6, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(NAPTR, KRW(NAPTR_HEADER), KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(KX, 2, KRW(FIXED_DNAME)) \
	ITEM(CERT, 5, KRW(REMAINDER)) \
	ITEM(DNAME, KRW(FIXED_DNAME)) \
	ITEM(OPT, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(APL, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(DS, 4, KRW(REMAINDER)) \
	ITEM(SSHFP, 2, KRW(REMAINDER)) \
	ITEM(IPSECKEY, 3, KRW(REMAINDER)) \
	ITEM(RRSIG, 18, KRW(FIXED_DNAME), KRW(REMAINDER)) \
	ITEM(NSEC, KRW(FIXED_DNAME), KRW(REMAINDER_MAYEMPTY)) \
	ITEM(DNSKEY, 4, KRW(REMAINDER)) \
	ITEM(DHCID, KRW(REMAINDER)) \
	ITEM(NSEC3, 7, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(NSEC3PARAM, 5, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(TLSA, 3, KRW(REMAINDER)) \
	ITEM(SMIMEA, KRW(REMAINDER)) \
	ITEM(CDS, 4, KRW(REMAINDER)) \
	ITEM(CDNSKEY, 4, KRW(REMAINDER)) \
	ITEM(OPENPGPKEY, KRW(REMAINDER)) \
	ITEM(CSYNC, 6, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(ZONEMD, 6, KRW(REMAINDER)) \
	ITEM(SVCB, 2, KRW(FIXED_DNAME), KRW(REMAINDER_MAYEMPTY)) \
	ITEM(HTTPS, 2, KRW(FIXED_DNAME), KRW(REMAINDER_MAYEMPTY)) \
	ITEM(DSYNC, 5, KRW(FIXED_DNAME)) \
	ITEM(SPF, KRW(REMAINDER)) \
	ITEM(NID, 10) \
	ITEM(L32, 6) \
	ITEM(L64, 10) \
	ITEM(LP, 2, KRW(FIXED_DNAME)) \
	ITEM(EUI48, 6) \
	ITEM(EUI64, 8) \
	ITEM(NXNAME, KRW(END)) /* redundant _END */ \
	ITEM(TKEY, KRW(FIXED_DNAME), KRW(REMAINDER)) \
	ITEM(TSIG, KRW(FIXED_DNAME), KRW(REMAINDER)) \
	ITEM(IXFR, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(AXFR, KRW(REMAINDER_MAYEMPTY)) \
	ITEM(ANY, KRW(END)) /* redundant _END */ \
	ITEM(URI, 4, KRW(REMAINDER)) \
	ITEM(CAA, 1, KRW(REMAINDER)) \
	ITEM(RESINFO, KRW(REMAINDER)) \
	ITEM(WALLET, KRW(REMAINDER)) \
	ITEM(ALIAS, KRW(DECOMPRESSIBLE_DNAME))

/*!
 * \brief Some (OBSOLETE) RR type descriptors.
 */
#define OBSOLETE_DESCRIPTOR_TYPES(ITEM) \
	ITEM(MD, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(MF, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(MB, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(MG, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(MR, KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(PX, 2, KRW(DECOMPRESSIBLE_DNAME), KRW(DECOMPRESSIBLE_DNAME)) \
	ITEM(NXT, KRW(DECOMPRESSIBLE_DNAME), KRW(REMAINDER))

_public_
const knot_rdata_descriptor_t *knot_get_rdata_descriptor(const uint16_t type)
{
	// We define descriptors as individual static variables.
	#define DEF_ITEM(name, ...) static const knot_rdata_descriptor_t \
		def_ ## name = {{__VA_ARGS__, KRW(END)}, #name};
	DESCRIPTOR_TYPES(DEF_ITEM)
	#undef DEF_ITEM

	// The default is separate, as we want the name to be NULL.
	static const knot_rdata_descriptor_t def_default =
		{ { KRW(REMAINDER_MAYEMPTY), KRW(END) }, NULL };

	switch (type) {
	#define SWITCH_ITEM(name, ...) case KNOT_RRTYPE_ ## name: return &(def_ ## name);
	DESCRIPTOR_TYPES(SWITCH_ITEM)
	#undef SWITCH_ITEM
	default: return &def_default;
	}
}

_public_
const knot_rdata_descriptor_t *knot_get_obsolete_rdata_descriptor(const uint16_t type)
{
	// We define descriptors as individual static variables.
	#define DEF_ITEM(name, ...) static const knot_rdata_descriptor_t \
		def_ ## name = {{__VA_ARGS__, KRW(END)}, #name};
	OBSOLETE_DESCRIPTOR_TYPES(DEF_ITEM)
	#undef DEF_ITEM

	// The default is separate, as we want the name to be NULL.
	static const knot_rdata_descriptor_t def_default =
		{ { KRW(REMAINDER), KRW(END) }, NULL };

	switch (type) {
	#define SWITCH_ITEM(name, ...) case KNOT_RRTYPE_ ## name: return &(def_ ## name);
	OBSOLETE_DESCRIPTOR_TYPES(SWITCH_ITEM)
	#undef SWITCH_ITEM
	default: return &def_default;
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

	static const uint16_t described_types[] = {
		#define CODE_ITEM(name, ...) KNOT_RRTYPE_ ## name,
		DESCRIPTOR_TYPES(CODE_ITEM)
		#undef CODE_ITEM
	};

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
	char *end;
	unsigned long n = strtoul(name, &end, 10);
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
