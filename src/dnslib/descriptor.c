#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

//#include "descriptor.h"
#include "dnslib.h"
/* TODO this has to be removed - move tokens to separate file */
#include "zoneparser.h"
#include "zparser.h"

enum desclen { DNSLIB_RRTYPE_DESCRIPTORS_LENGTH = 32770 }; // used to be 101

/* Taken from RFC 1035, section 3.2.4.  */
static dnslib_lookup_table_t dns_rrclasses[] = {
	{ DNSLIB_CLASS_IN, "IN" },	/* the Internet */
	{ DNSLIB_CLASS_CS, "CS" },	/* the CSNET class (Obsolete) */
	{ DNSLIB_CLASS_CH, "CH" },	/* the CHAOS class */
	{ DNSLIB_CLASS_HS, "HS" },	/* Hesiod */
	{ 0, NULL }
};
static dnslib_rrtype_descriptor_t
       dnslib_rrtype_descriptors[DNSLIB_RRTYPE_DESCRIPTORS_LENGTH] = {
        /* 0 */
  	{ 0, 0, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 1 */
  	{ DNSLIB_RRTYPE_A, T_A, "A", 1, { DNSLIB_RDATA_WF_A }, true },
  	/* 2 */
  	{ DNSLIB_RRTYPE_NS, T_NS, "NS", 1,
	{ DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 3 */
  	{ DNSLIB_RRTYPE_MD, T_MD, "MD", 1,
  	  { DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME }, true },
  	/* 4 */
  	{ DNSLIB_RRTYPE_MF, T_MF, "MF", 1,
  	  { DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME }, true },
  	/* 5 */
  	{ DNSLIB_RRTYPE_CNAME, T_CNAME, "CNAME", 1,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 6 */
  	{ DNSLIB_RRTYPE_SOA, T_SOA, "SOA", 7,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME, DNSLIB_RDATA_WF_COMPRESSED_DNAME,
	    DNSLIB_RDATA_WF_LONG, DNSLIB_RDATA_WF_LONG, DNSLIB_RDATA_WF_LONG,
	    DNSLIB_RDATA_WF_LONG, DNSLIB_RDATA_WF_LONG }, true },
  	/* 7 */
  	{ DNSLIB_RRTYPE_MB, T_MB, "MB", 1,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 8 */
  	{ DNSLIB_RRTYPE_MG, T_MG, "MG", 1,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 9 */
  	{ DNSLIB_RRTYPE_MR, T_MR, "MR", 1,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
    	/* 10 */
  	{ DNSLIB_RRTYPE_NULL, T_NULL, NULL, 1,
  	  { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 11 */
  	{ DNSLIB_RRTYPE_WKS, T_WKS, "WKS", 2,
	  { DNSLIB_RDATA_WF_A, DNSLIB_RDATA_WF_BINARY }, true },
  	/* 12 */
  	{ DNSLIB_RRTYPE_PTR, T_PTR, "PTR", 1,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 13 */
  	{ DNSLIB_RRTYPE_HINFO, T_HINFO, "HINFO", 2,
  	  { DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT }, true },
  	/* 14 */
  	{ DNSLIB_RRTYPE_MINFO, T_MINFO, "MINFO", 2,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME,
	    DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 15 */
  	{ DNSLIB_RRTYPE_MX, T_MX, "MX", 2,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 16 */ /* This is obscure, but I guess there's no other way */
	{ DNSLIB_RRTYPE_TXT, T_TXT, "TXT", DNSLIB_MAX_RDATA_ITEMS,
  	  { DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT }, false },
  	/* 17 */
  	{ DNSLIB_RRTYPE_RP, T_RP, "RP", 2,
  	  { DNSLIB_RDATA_WF_COMPRESSED_DNAME,
	    DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 18 */
  	{ DNSLIB_RRTYPE_AFSDB, T_AFSDB, "AFSDB", 2,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 19 */
  	{ DNSLIB_RRTYPE_X25, T_X25, "X25", 1,
  	  { DNSLIB_RDATA_WF_TEXT }, true },
  	/* 20 */
  	{ DNSLIB_RRTYPE_ISDN, T_ISDN, "ISDN", 2,
  	  { DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT }, false },
  	/* 21 */
  	{ DNSLIB_RRTYPE_RT, T_RT, "RT", 2,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_COMPRESSED_DNAME }, true },
  	/* 22 */
  	{ DNSLIB_RRTYPE_NSAP, T_NSAP, "NSAP", 1,
  	  { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 23 */
  	{ 23, 0, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 24 */
  	{ DNSLIB_RRTYPE_SIG, T_SIG, "SIG", 9,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BYTE,
	    DNSLIB_RDATA_WF_LONG, DNSLIB_RDATA_WF_LONG, DNSLIB_RDATA_WF_LONG,
	    DNSLIB_RDATA_WF_SHORT,DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME,
	    DNSLIB_RDATA_WF_BINARY }, true },
  	/* 25 */
  	{ DNSLIB_RRTYPE_KEY, T_KEY, "KEY", 4,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_BYTE,
	    DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BINARY }, true },
  	/* 26 */
  	{ DNSLIB_RRTYPE_PX, T_PX, "PX", 3,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME,
  	    DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME }, true },
  	/* 27 */
  	{ 27, 0, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 28 */
  	{ DNSLIB_RRTYPE_AAAA, T_AAAA, "AAAA", 1,
  	  { DNSLIB_RDATA_WF_AAAA }, true },
  	/* 29 */
  	{ DNSLIB_RRTYPE_LOC, T_LOC, "LOC", 1,
  	  { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 30 */
  	{ DNSLIB_RRTYPE_NXT, T_NXT, "NXT", 2,
  	  { DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME,
	    DNSLIB_RDATA_WF_BINARY }, true },
  	/* 31 */
  	{ 31, 0, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 32 */
  	{ 32, 0, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 33 */
  	{ DNSLIB_RRTYPE_SRV, T_SRV, "SRV", 4,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_SHORT,
	    DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME },
	  true },
  	/* 34 */
  	{ 34, 0, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 35 */
  	{ DNSLIB_RRTYPE_NAPTR, T_NAPTR, "NAPTR", 6,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME }, true },
  	/* 36 */
  	{ DNSLIB_RRTYPE_KX, T_KX, "KX", 2,
  	  { DNSLIB_RDATA_WF_SHORT,
	    DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME }, true },
  	/* 37 */
  	{ DNSLIB_RRTYPE_CERT, T_CERT, "CERT", 4,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_SHORT,
	    DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BINARY }, true },
  	/* 38 */
  	{ DNSLIB_RRTYPE_A6, T_A6, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 39 */
  	{ DNSLIB_RRTYPE_DNAME, T_DNAME, "DNAME", 1,
  	  { DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME }, true },
  	/* 40 */
  	{ 40, 0, NULL, 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 41 */
	/* OPT has its parser token, but should never be in zone file... */
  	{ DNSLIB_RRTYPE_OPT, T_OPT, "OPT", 1,
  	  { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 42 */
	{ DNSLIB_RRTYPE_APL, T_APL, "APL", DNSLIB_MAX_RDATA_ITEMS,
  	  { DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
  	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL,
	    DNSLIB_RDATA_WF_APL, DNSLIB_RDATA_WF_APL }, false },
  	/* 43 */
  	{ DNSLIB_RRTYPE_DS, T_DS, "DS", 4,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_BYTE,
	  DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BINARY }, true },
  	/* 44 */
  	{ DNSLIB_RRTYPE_SSHFP, T_SSHFP, "SSHFP", 3,
  	  { DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BYTE,
	    DNSLIB_RDATA_WF_BINARY }, true },
  	/* 45 */
  	{ DNSLIB_RRTYPE_IPSECKEY, T_IPSECKEY, "IPSECKEY", 5,
  	  { DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BYTE,
	    DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_IPSECGATEWAY,
  	    DNSLIB_RDATA_WF_BINARY }, false },
  	/* 46 */
  	{ DNSLIB_RRTYPE_RRSIG, T_RRSIG, "RRSIG", 9,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_BYTE,
	    DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_LONG,
  	    DNSLIB_RDATA_WF_LONG, DNSLIB_RDATA_WF_LONG,
	    DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_BINARY,
	    DNSLIB_RDATA_WF_BINARY }, true },
  	/* 47 */
  	{ DNSLIB_RRTYPE_NSEC, T_NSEC, "NSEC", 2,
	  { DNSLIB_RDATA_WF_BINARY, DNSLIB_RDATA_WF_BINARY }, true },
  	/* 48 */
  	{ DNSLIB_RRTYPE_DNSKEY, T_DNSKEY, "DNSKEY", 4,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_BYTE,
	    DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BINARY }, true },
  	/* 49 */
  	{ DNSLIB_RRTYPE_DHCID, T_DHCID, "DHCID", 1, { DNSLIB_RDATA_WF_BINARY }, true },
  	/* 50 */
  	{ DNSLIB_RRTYPE_NSEC3, T_NSEC3, "NSEC3", 6,
  	  { DNSLIB_RDATA_WF_BYTE, /* hash type */
  	    DNSLIB_RDATA_WF_BYTE, /* flags */
  	    DNSLIB_RDATA_WF_SHORT, /* iterations */
  	    DNSLIB_RDATA_WF_BINARYWITHLENGTH, /* salt */
  	    DNSLIB_RDATA_WF_BINARYWITHLENGTH, /* next hashed name */
  	    DNSLIB_RDATA_WF_BINARY /* type bitmap */ }, true },
  	/* 51 */
  	{ DNSLIB_RRTYPE_NSEC3PARAM, T_NSEC3PARAM, "NSEC3PARAM", 4,
  	  { DNSLIB_RDATA_WF_BYTE, /* hash type */
  	    DNSLIB_RDATA_WF_BYTE, /* flags */
  	    DNSLIB_RDATA_WF_SHORT, /* iterations */
  	    DNSLIB_RDATA_WF_BINARYWITHLENGTH /* salt */ }, true },
  	/* 52 */


    /* In NSD they have indices between 52 and 99 filled with
     unknown types. TODO add here if it's really needed? */
     /* it is indeed needed, in rrtype_from_string */

    /* There's a GNU extension that works like this: [first ... last] = value */

  	/* 99 */
	[99] = { DNSLIB_RRTYPE_SPF, T_SPF, "SPF", DNSLIB_MAX_RDATA_ITEMS,
  	  { DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
  	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT,
	    DNSLIB_RDATA_WF_TEXT, DNSLIB_RDATA_WF_TEXT }, false },
  	/* 32769 */
  	[32769] = { DNSLIB_RRTYPE_DLV, T_DLV, "DLV", 4,
  	  { DNSLIB_RDATA_WF_SHORT, DNSLIB_RDATA_WF_BYTE,
	    DNSLIB_RDATA_WF_BYTE, DNSLIB_RDATA_WF_BINARY } },
};

static dnslib_lookup_table_t *dnslib_lookup_by_name(dnslib_lookup_table_t *table,
                                             const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0) {
			return table;
		}
		table++;
	}

	return NULL;
}

static dnslib_lookup_table_t *dnslib_lookup_by_id(dnslib_lookup_table_t *table,
					   int id)
{
	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*!
 * \brief Strlcpy - safe string copy function, based on FreeBSD implementation.
 *
 * http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/string/
 *
 * \param dst Destination string.
 * \param src Source string.
 * \param siz How many characters to copy - 1.
 *
 * \return strlen(src), if retval >= siz, truncation occurred.
 */
size_t dnslib_strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0) {
				break;
			}
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0) {
			*d = '\0';        /* NUL-terminate dst */
		}
		while (*s++)
			;
	}

	return(s - src - 1);        /* count does not include NUL */
}

dnslib_rrtype_descriptor_t *dnslib_rrtype_descriptor_by_type(uint16_t type)
{
	if (type < DNSLIB_RRTYPE_LAST + 1) {
		return &dnslib_rrtype_descriptors[type];
	} else if (type == DNSLIB_RRTYPE_DLV) {
		return &dnslib_rrtype_descriptors[DNSLIB_RRTYPE_DLV];
	}
	return &dnslib_rrtype_descriptors[0];
}

/* I see a lot of potential here to speed up zone parsing - this is O(n) *
 * could be better */
dnslib_rrtype_descriptor_t *dnslib_rrtype_descriptor_by_name(const char *name)
{
	int i;

	for (i = 0; i < DNSLIB_RRTYPE_LAST + 1; ++i) {
		if (dnslib_rrtype_descriptors[i].name &&
		    strcasecmp(dnslib_rrtype_descriptors[i].name, name) == 0) {
			return &dnslib_rrtype_descriptors[i];
		}
	}

	if (dnslib_rrtype_descriptors[DNSLIB_RRTYPE_DLV].name &&
	    strcasecmp(dnslib_rrtype_descriptors[DNSLIB_RRTYPE_DLV].name,
	                              name) == 0) {
		return &dnslib_rrtype_descriptors[DNSLIB_RRTYPE_DLV];
	}

	return NULL;
}

const char *dnslib_rrtype_to_string(uint16_t rrtype)
{
	static char buf[20];
	dnslib_rrtype_descriptor_t *descriptor =
	        dnslib_rrtype_descriptor_by_type(rrtype);
	if (descriptor->name) {
		return descriptor->name;
	} else {
		snprintf(buf, sizeof(buf), "TYPE%d", (int) rrtype);
		return buf;
	}
}

uint16_t dnslib_rrtype_from_string(const char *name)
{
	char *end;
	long rrtype;
	dnslib_rrtype_descriptor_t *entry;

	entry = dnslib_rrtype_descriptor_by_name(name);
	if (entry) {
		return entry->type;
	}

	if (strlen(name) < 5) {
		return 0;
	}

	if (strncasecmp(name, "TYPE", 4) != 0) {
		return 0;
	}

	if (!isdigit((int)name[4])) {
		return 0;
	}

	/* The rest from the string must be a number.  */
	rrtype = strtol(name + 4, &end, 10);
	if (*end != '\0') {
		return 0;
	}
	if (rrtype < 0 || rrtype > 65535L) {
		return 0;
	}

	return (uint16_t) rrtype;
}

const char *dnslib_rrclass_to_string(uint16_t rrclass)
{
	static char buf[20];
	dnslib_lookup_table_t *entry = dnslib_lookup_by_id(dns_rrclasses,
							   rrclass);
	if (entry) {
		assert(strlen(entry->name) < sizeof(buf));
		dnslib_strlcpy(buf, entry->name, sizeof(buf));
	} else {
		snprintf(buf, sizeof(buf), "CLASS%d", (int) rrclass);
	}
	return buf;
}

uint16_t dnslib_rrclass_from_string(const char *name)
{
	char *end;
	long rrclass;
	dnslib_lookup_table_t *entry;

	entry = dnslib_lookup_by_name(dns_rrclasses, name);
	if (entry) {
		return (uint16_t) entry->id;
	}

	if (strlen(name) < 6) {
		return 0;
	}

	if (strncasecmp(name, "CLASS", 5) != 0) {
		return 0;
	}

	if (!isdigit((int)name[5])) {
		return 0;
	}

	// The rest from the string must be a number.
	rrclass = strtol(name + 5, &end, 10);
	if (*end != '\0') {
		return 0;
	}
	if (rrclass < 0 || rrclass > 65535L) {
		return 0;
	}

	return (uint16_t) rrclass;
}

