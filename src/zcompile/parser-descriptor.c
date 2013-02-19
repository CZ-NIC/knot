/*!
 * \file parser-descriptor.c
 *
 * \author Modifications by Jan Kadlec <jan.kadlec@nic.cz>,
 *         most of the work by NLnet Labs.
 *         Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * \brief Contains resource record descriptor and its API
 *
 * \addtogroup zoneparser
 * @{
 */

/*
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

//#include "common.h"
#include "zcompile/parser-descriptor.h"
/* TODO this has to be removed - move tokens to separate file
	but can it be done?) */
#include "zcompile/zcompile.h"
/* FIXME: Generate .y and .l to zoneparser/ */
#include "zparser.h"

enum desclen { PARSER_RRTYPE_DESCRIPTORS_LENGTH = 65536 }; // used to be 101

/* Taken from RFC 1035, section 3.2.4.  */
static knot_lookup_table_t dns_rrclasses[] = {
	{ PARSER_CLASS_IN, "IN" },	/* the Internet */
	{ PARSER_CLASS_CS, "CS" },	/* the CSNET class (Obsolete) */
	{ PARSER_CLASS_CH, "CH" },	/* the CHAOS class */
	{ PARSER_CLASS_HS, "HS" },	/* Hesiod */
	{ 0, NULL }
};
static parser_rrtype_descriptor_t
       knot_rrtype_descriptors[PARSER_RRTYPE_DESCRIPTORS_LENGTH] = {
	/* 0 */
	{ 0, 0, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 1 */
	{ PARSER_RRTYPE_A, T_A, "A", 1, { PARSER_RDATA_WF_A }, true },
	/* 2 */
	{ PARSER_RRTYPE_NS, T_NS, "NS", 1,
	{ PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 3 */
	{ PARSER_RRTYPE_MD, T_MD, "MD", 1,
	  { PARSER_RDATA_WF_UNCOMPRESSED_DNAME }, true },
	/* 4 */
	{ PARSER_RRTYPE_MF, T_MF, "MF", 1,
	  { PARSER_RDATA_WF_UNCOMPRESSED_DNAME }, true },
	/* 5 */
	{ PARSER_RRTYPE_CNAME, T_CNAME, "CNAME", 1,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 6 */
	{ PARSER_RRTYPE_SOA, T_SOA, "SOA", 7,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME, PARSER_RDATA_WF_COMPRESSED_DNAME,
	    PARSER_RDATA_WF_LONG, PARSER_RDATA_WF_LONG, PARSER_RDATA_WF_LONG,
	    PARSER_RDATA_WF_LONG, PARSER_RDATA_WF_LONG }, true },
	/* 7 */
	{ PARSER_RRTYPE_MB, T_MB, "MB", 1,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 8 */
	{ PARSER_RRTYPE_MG, T_MG, "MG", 1,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 9 */
	{ PARSER_RRTYPE_MR, T_MR, "MR", 1,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 10 */
	{ PARSER_RRTYPE_NULL, T_NULL, NULL, 1,
	  { PARSER_RDATA_WF_BINARY }, true },
	/* 11 */
	{ PARSER_RRTYPE_WKS, T_WKS, "WKS", 2,
	  { PARSER_RDATA_WF_A, PARSER_RDATA_WF_BINARY }, true },
	/* 12 */
	{ PARSER_RRTYPE_PTR, T_PTR, "PTR", 1,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 13 */
	{ PARSER_RRTYPE_HINFO, T_HINFO, "HINFO", 2,
	  { PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT }, true },
	/* 14 */
	{ PARSER_RRTYPE_MINFO, T_MINFO, "MINFO", 2,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME,
	    PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 15 */
	{ PARSER_RRTYPE_MX, T_MX, "MX", 2,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 16 */ /* This is obscure, but I guess there's no other way */
	{ PARSER_RRTYPE_TXT, T_TXT, "TXT", PARSER_MAX_RDATA_ITEMS,
	  { PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT }, false },
	/* 17 */
	{ PARSER_RRTYPE_RP, T_RP, "RP", 2,
	  { PARSER_RDATA_WF_COMPRESSED_DNAME,
	    PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 18 */
	{ PARSER_RRTYPE_AFSDB, T_AFSDB, "AFSDB", 2,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 19 */
	{ PARSER_RRTYPE_X25, T_X25, "X25", 1,
	  { PARSER_RDATA_WF_TEXT }, true },
	/* 20 */
	{ PARSER_RRTYPE_ISDN, T_ISDN, "ISDN", 2,
	  { PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT }, false },
	/* 21 */
	{ PARSER_RRTYPE_RT, T_RT, "RT", 2,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_COMPRESSED_DNAME }, true },
	/* 22 */
	{ PARSER_RRTYPE_NSAP, T_NSAP, "NSAP", 1,
	  { PARSER_RDATA_WF_BINARY }, true },
	/* 23 */
	{ 23, 0, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 24 */
	{ PARSER_RRTYPE_SIG, T_SIG, "SIG", 9,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BYTE,
	    PARSER_RDATA_WF_LONG, PARSER_RDATA_WF_LONG, PARSER_RDATA_WF_LONG,
	    PARSER_RDATA_WF_SHORT,PARSER_RDATA_WF_UNCOMPRESSED_DNAME,
	    PARSER_RDATA_WF_BINARY }, true },
	/* 25 */
	{ PARSER_RRTYPE_KEY, T_KEY, "KEY", 4,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_BYTE,
	    PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BINARY }, true },
	/* 26 */
	{ PARSER_RRTYPE_PX, T_PX, "PX", 3,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_UNCOMPRESSED_DNAME,
	    PARSER_RDATA_WF_UNCOMPRESSED_DNAME }, true },
	/* 27 */
	{ 27, 0, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 28 */
	{ PARSER_RRTYPE_AAAA, T_AAAA, "AAAA", 1,
	  { PARSER_RDATA_WF_AAAA }, true },
	/* 29 */
	{ PARSER_RRTYPE_LOC, T_LOC, "LOC", 1,
	  { PARSER_RDATA_WF_BINARY }, true },
	/* 30 */
	{ PARSER_RRTYPE_NXT, T_NXT, "NXT", 2,
	  { PARSER_RDATA_WF_UNCOMPRESSED_DNAME,
	    PARSER_RDATA_WF_BINARY }, true },
	/* 31 */
	{ 31, 0, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 32 */
	{ 32, 0, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 33 */
	{ PARSER_RRTYPE_SRV, T_SRV, "SRV", 4,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_SHORT,
	    PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_UNCOMPRESSED_DNAME },
	  true },
	/* 34 */
	{ 34, 0, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 35 */
	{ PARSER_RRTYPE_NAPTR, T_NAPTR, "NAPTR", 6,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_UNCOMPRESSED_DNAME }, true },
	/* 36 */
	{ PARSER_RRTYPE_KX, T_KX, "KX", 2,
	  { PARSER_RDATA_WF_SHORT,
	    PARSER_RDATA_WF_UNCOMPRESSED_DNAME }, true },
	/* 37 */
	{ PARSER_RRTYPE_CERT, T_CERT, "CERT", 4,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_SHORT,
	    PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BINARY }, true },
	/* 38 */
	{ PARSER_RRTYPE_A6, T_A6, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 39 */
	{ PARSER_RRTYPE_DNAME, T_DNAME, "DNAME", 1,
	  { PARSER_RDATA_WF_UNCOMPRESSED_DNAME }, true },
	/* 40 */
	{ 40, 0, NULL, 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 41 */
	/* OPT has its parser token, but should never be in zone file... */
	{ PARSER_RRTYPE_OPT, T_OPT, "OPT", 1,
	  { PARSER_RDATA_WF_BINARY }, true },
	/* 42 */
	{ PARSER_RRTYPE_APL, T_APL, "APL", PARSER_MAX_RDATA_ITEMS,
	  { PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL,
	    PARSER_RDATA_WF_APL, PARSER_RDATA_WF_APL }, false },
	/* 43 */
	{ PARSER_RRTYPE_DS, T_DS, "DS", 4,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_BYTE,
	  PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BINARY }, true },
	/* 44 */
	{ PARSER_RRTYPE_SSHFP, T_SSHFP, "SSHFP", 3,
	  { PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BYTE,
	    PARSER_RDATA_WF_BINARY }, true },
	/* 45 */
	{ PARSER_RRTYPE_IPSECKEY, T_IPSECKEY, "IPSECKEY", 5,
	  { PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BYTE,
	    PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_IPSECGATEWAY,
	    PARSER_RDATA_WF_BINARY }, false },
	/* 46 */
	{ PARSER_RRTYPE_RRSIG, T_RRSIG, "RRSIG", 9,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_BYTE,
	    PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_LONG,
	    PARSER_RDATA_WF_LONG, PARSER_RDATA_WF_LONG,
	    PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_BINARY,
	    PARSER_RDATA_WF_BINARY }, true },
	/* 47 */
	{ PARSER_RRTYPE_NSEC, T_NSEC, "NSEC", 2,
	  { PARSER_RDATA_WF_BINARY, PARSER_RDATA_WF_BINARY }, true },
	/* 48 */
	{ PARSER_RRTYPE_DNSKEY, T_DNSKEY, "DNSKEY", 4,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_BYTE,
	    PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BINARY }, true },
	/* 49 */
	{ PARSER_RRTYPE_DHCID, T_DHCID, "DHCID", 1, { PARSER_RDATA_WF_BINARY }, true },
	/* 50 */
	{ PARSER_RRTYPE_NSEC3, T_NSEC3, "NSEC3", 6,
	  { PARSER_RDATA_WF_BYTE, /* hash type */
	    PARSER_RDATA_WF_BYTE, /* flags */
	    PARSER_RDATA_WF_SHORT, /* iterations */
	    PARSER_RDATA_WF_BINARYWITHLENGTH, /* salt */
	    PARSER_RDATA_WF_BINARYWITHLENGTH, /* next hashed name */
	    PARSER_RDATA_WF_BINARY /* type bitmap */ }, true },
	/* 51 */
	{ PARSER_RRTYPE_NSEC3PARAM, T_NSEC3PARAM, "NSEC3PARAM", 4,
	  { PARSER_RDATA_WF_BYTE, /* hash type */
	    PARSER_RDATA_WF_BYTE, /* flags */
	    PARSER_RDATA_WF_SHORT, /* iterations */
	    PARSER_RDATA_WF_BINARYWITHLENGTH /* salt */ }, true },
	/* 52 TLSA */
        { PARSER_RRTYPE_TLSA, T_TLSA, "TLSA", 3,
          { PARSER_RDATA_WF_BYTE,
            PARSER_RDATA_WF_BYTE,
            PARSER_RDATA_WF_BYTE,
            PARSER_RDATA_WF_BINARY}, true }, 


    /* In NSD they have indices between 52 and 99 filled with
     unknown types. TODO add here if it's really needed? */
     /* it is indeed needed, in rrtype_from_string */

    /* There's a GNU extension that works like this: [first ... last] = value */

        [53 ... 98] = { PARSER_RRTYPE_TYPEXXX, T_UTYPE, NULL, 1, { PARSER_RDATA_WF_BINARY }},

	/* 99 */
	[99] = { PARSER_RRTYPE_SPF, T_SPF, "SPF", PARSER_MAX_RDATA_ITEMS,
	  { PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT,
	    PARSER_RDATA_WF_TEXT, PARSER_RDATA_WF_TEXT }, false },
	[100 ... 32768] = { PARSER_RRTYPE_TYPEXXX, T_UTYPE, NULL, 1, { PARSER_RDATA_WF_BINARY }},
	/* 32769 */
	[32769] = { PARSER_RRTYPE_DLV, T_DLV, "DLV", 4,
	  { PARSER_RDATA_WF_SHORT, PARSER_RDATA_WF_BYTE,
	    PARSER_RDATA_WF_BYTE, PARSER_RDATA_WF_BINARY }}, 
	[32770 ... 65535] = { PARSER_RRTYPE_TYPEXXX, T_UTYPE, NULL, 1, { PARSER_RDATA_WF_BINARY }}
};

parser_rrtype_descriptor_t *parser_rrtype_descriptor_by_type(uint16_t type)
{
	if (type <= 65535) {
		return &knot_rrtype_descriptors[type];
	}
	return &knot_rrtype_descriptors[0];
}

/* I see a lot of potential here to speed up zone parsing - this is O(n) *
 * could be better */
parser_rrtype_descriptor_t *parser_rrtype_descriptor_by_name(const char *name)
{
	if (!name) {
		return NULL;
	}

	if (strcasecmp(name, "IN") == 0) {
		return NULL;
	}

	if (isdigit((int)name[0])) {
		return NULL;
	}

//	/* The most common - A and NS. */
//	if (strcasecmp(name, "NS") == 0) {
//		return &knot_rrtype_descriptors[2];
//	}

//	if (strcasecmp(name, "A") == 0) {
//		return &knot_rrtype_descriptors[1];
//	}

//	/* Then RRSIG */
//	if (strcasecmp(name, "RRSIG") == 0) {
//		return &knot_rrtype_descriptors[46];
//	}

//	/* Then DS */
//	if (strcasecmp(name, "DS") == 0) {
//		return &knot_rrtype_descriptors[43];
//	}
//	/* Then NSEC3 */
//	if (strcasecmp(name, "NSEC3") == 0) {
//		return &knot_rrtype_descriptors[50];
//	}
//	/* Then NSEC */
//	if (strcasecmp(name, "NSEC") == 0) {
//		return &knot_rrtype_descriptors[47];
//	}

	int i;

	for (i = 0; i < PARSER_RRTYPE_LAST + 1; ++i) {
		if (knot_rrtype_descriptors[i].name &&
		    strcasecmp(knot_rrtype_descriptors[i].name, name) == 0) {
			return &knot_rrtype_descriptors[i];
		}
	}

	if (knot_rrtype_descriptors[PARSER_RRTYPE_DLV].name &&
	    strcasecmp(knot_rrtype_descriptors[PARSER_RRTYPE_DLV].name,
				      name) == 0) {
		return &knot_rrtype_descriptors[PARSER_RRTYPE_DLV];
	}

	return NULL;
}

const char *parser_rrtype_to_string(uint16_t rrtype)
{
	static char buf[20];
	parser_rrtype_descriptor_t *descriptor =
		parser_rrtype_descriptor_by_type(rrtype);
	if (descriptor->name) {
		return descriptor->name;
	} else {
		snprintf(buf, sizeof(buf), "TYPE%d", (int) rrtype);
		return buf;
	}
}

uint16_t parser_rrtype_from_string(const char *name)
{
	char *end;
	long rrtype;
	parser_rrtype_descriptor_t *entry;
	if (!name) {
		return 0;
	}

	entry = parser_rrtype_descriptor_by_name(name);
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

const char *parser_rrclass_to_string(uint16_t rrclass)
{
	static char buf[20];
	knot_lookup_table_t *entry = knot_lookup_by_id(dns_rrclasses,
							   rrclass);
	if (entry) {
		assert(strlen(entry->name) < sizeof(buf));
		knot_strlcpy(buf, entry->name, sizeof(buf));
	} else {
		snprintf(buf, sizeof(buf), "CLASS%d", (int) rrclass);
	}
	return buf;
}

uint16_t parser_rrclass_from_string(const char *name)
{
	char *end;
	long rrclass;
	knot_lookup_table_t *entry;

	entry = knot_lookup_by_name(dns_rrclasses, name);
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

/*! @} */
