/*!
 * \file descriptor.c
 *
 * \author Modifications by Jan Kadlec <jan.kadlec@nic.cz>,
 *         most of the work by NLnet labs.
 *         Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * \note Most of the constants and functions were taken from NSD's dns.c.
 *
 * \addtogroup libknot
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

#include "libknot.h"

enum desclen { KNOT_RRTYPE_DESCRIPTORS_LENGTH = 32770 }; // used to be 101

/*!
 * \brief Table for linking RR class constants to their textual representation.
 */
static knot_lookup_table_t dns_rrclasses[] = {
	{ KNOT_CLASS_IN, "IN" },	/* the Internet */
	{ KNOT_CLASS_CS, "CS" },	/* the CSNET class (Obsolete) */
	{ KNOT_CLASS_CH, "CH" },	/* the CHAOS class */
	{ KNOT_CLASS_HS, "HS" },	/* Hesiod */
	{ 0, NULL }
};

/*! \brief RR type descriptors. */
static knot_rrtype_descriptor_t
       knot_rrtype_descriptors[KNOT_RRTYPE_DESCRIPTORS_LENGTH] = {
        /* 0 */
  	{ 0, NULL, 1, { KNOT_RDATA_WF_BINARY }, { KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 1 */
  	{ KNOT_RRTYPE_A, "A", 1, { KNOT_RDATA_WF_A }, { KNOT_RDATA_ZF_A }, true },
  	/* 2 */
  	{ KNOT_RRTYPE_NS, "NS", 1,
	{ KNOT_RDATA_WF_COMPRESSED_DNAME }, { KNOT_RDATA_ZF_DNAME }, true },
  	/* 3 */
  	{ KNOT_RRTYPE_MD, "MD", 1,
  	  { KNOT_RDATA_WF_UNCOMPRESSED_DNAME }, { KNOT_RDATA_ZF_DNAME }, true },
  	/* 4 */
  	{ KNOT_RRTYPE_MF, "MF", 1,
  	  { KNOT_RDATA_WF_UNCOMPRESSED_DNAME }, { KNOT_RDATA_ZF_DNAME }, true },
  	/* 5 */
  	{ KNOT_RRTYPE_CNAME, "CNAME", 1,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME }, { KNOT_RDATA_ZF_DNAME }, true },
  	/* 6 */
  	{ KNOT_RRTYPE_SOA, "SOA", 7,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME, KNOT_RDATA_WF_COMPRESSED_DNAME,
	    KNOT_RDATA_WF_LONG, KNOT_RDATA_WF_LONG, KNOT_RDATA_WF_LONG,
	    KNOT_RDATA_WF_LONG, KNOT_RDATA_WF_LONG },
	  { KNOT_RDATA_ZF_DNAME, KNOT_RDATA_ZF_DNAME, KNOT_RDATA_ZF_PERIOD, KNOT_RDATA_ZF_PERIOD,
	    KNOT_RDATA_ZF_PERIOD, KNOT_RDATA_ZF_PERIOD, KNOT_RDATA_ZF_PERIOD },
	  true },
  	/* 7 */
  	{ KNOT_RRTYPE_MB, "MB", 1,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME }, { KNOT_RDATA_ZF_DNAME }, true },
  	/* 8 */
  	{ KNOT_RRTYPE_MG, "MG", 1,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME }, { KNOT_RDATA_ZF_DNAME }, true },
  	/* 9 */
  	{ KNOT_RRTYPE_MR, "MR", 1,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME }, { KNOT_RDATA_ZF_DNAME }, true },
    	/* 10 */
  	{ KNOT_RRTYPE_NULL, NULL, 1,
  	  { KNOT_RDATA_WF_BINARY }, { KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 11 */
  	{ KNOT_RRTYPE_WKS, "WKS", 2,
	  { KNOT_RDATA_WF_A, KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_A, KNOT_RDATA_ZF_SERVICES }, true },
  	/* 12 */
  	{ KNOT_RRTYPE_PTR, "PTR", 1,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_DNAME }, true },
  	/* 13 */
  	{ KNOT_RRTYPE_HINFO, "HINFO", 2,
  	  { KNOT_RDATA_WF_TEXT_SINGLE, KNOT_RDATA_WF_TEXT_SINGLE },
	  { KNOT_RDATA_ZF_TEXT, KNOT_RDATA_ZF_TEXT }, true },
  	/* 14 */
  	{ KNOT_RRTYPE_MINFO, "MINFO", 2,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME,
	    KNOT_RDATA_WF_COMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_DNAME, KNOT_RDATA_ZF_DNAME }, true },
  	/* 15 */
  	{ KNOT_RRTYPE_MX, "MX", 2,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_COMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_DNAME }, true },
  	/* 16 */ /* This is obscure, but I guess there's no other way */
	{ KNOT_RRTYPE_TXT, "TXT", 1,
  	  { KNOT_RDATA_WF_TEXT },
	  { KNOT_RDATA_ZF_TEXT },
	    false },
  	/* 17 */
  	{ KNOT_RRTYPE_RP, "RP", 2,
  	  { KNOT_RDATA_WF_COMPRESSED_DNAME,
	    KNOT_RDATA_WF_COMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_DNAME, KNOT_RDATA_ZF_DNAME }, true },
  	/* 18 */
  	{ KNOT_RRTYPE_AFSDB, "AFSDB", 2,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_COMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_DNAME }, true },
  	/* 19 */
  	{ KNOT_RRTYPE_X25, "X25", 1,
  	  { KNOT_RDATA_WF_TEXT_SINGLE },
	  { KNOT_RDATA_ZF_TEXT }, true },
  	/* 20 */
  	{ KNOT_RRTYPE_ISDN, "ISDN", 2,
  	  { KNOT_RDATA_WF_TEXT_SINGLE, KNOT_RDATA_WF_TEXT_SINGLE },
	  { KNOT_RDATA_ZF_TEXT, KNOT_RDATA_ZF_TEXT }, false },
  	/* 21 */
  	{ KNOT_RRTYPE_RT, "RT", 2,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_COMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_DNAME }, true },
  	/* 22 */
  	{ KNOT_RRTYPE_NSAP, "NSAP", 1,
  	  { KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_NSAP }, true },
  	/* 23 */
  	{ 23, NULL, 1, { KNOT_RDATA_WF_BINARY },
	{ KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 24 */
  	{ KNOT_RRTYPE_SIG, "SIG", 9,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BYTE,
	    KNOT_RDATA_WF_LONG, KNOT_RDATA_WF_LONG, KNOT_RDATA_WF_LONG,
	    KNOT_RDATA_WF_SHORT,KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	    KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_RRTYPE, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_PERIOD,
	    KNOT_RDATA_ZF_TIME, KNOT_RDATA_ZF_TIME, KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_DNAME,
	    KNOT_RDATA_ZF_BASE64 },
	    true },
  	/* 25 */
  	{ KNOT_RRTYPE_KEY, "KEY", 4,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_BYTE,
	    KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BINARY },
	    { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_ALGORITHM,
	    KNOT_RDATA_ZF_BASE64 }, true },
  	/* 26 */
  	{ KNOT_RRTYPE_PX, "PX", 3,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
  	    KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
	    { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_DNAME, KNOT_RDATA_ZF_DNAME }, true },
  	/* 27 */
	{ 27, NULL, 1, { KNOT_RDATA_WF_BINARY }, { KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 28 */
  	{ KNOT_RRTYPE_AAAA, "AAAA", 1,
  	  { KNOT_RDATA_WF_AAAA },
	  { KNOT_RDATA_ZF_AAAA }, true },
  	/* 29 */
  	{ KNOT_RRTYPE_LOC, "LOC", 1,
  	  { KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_LOC }, true },
  	/* 30 */
  	{ KNOT_RRTYPE_NXT, "NXT", 2,
  	  { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
	    KNOT_RDATA_WF_BINARY },
	    { KNOT_RDATA_ZF_DNAME, KNOT_RDATA_ZF_NXT }, true },
  	/* 31 */
  	{ 31, NULL, 1, { KNOT_RDATA_WF_BINARY }, { KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 32 */
  	{ 32, NULL, 1, { KNOT_RDATA_WF_BINARY }, { KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 33 */
  	{ KNOT_RRTYPE_SRV, "SRV", 4,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_SHORT,
	    KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_DNAME },
	  true },
  	/* 34 */
  	{ 34, NULL, 1, { KNOT_RDATA_WF_BINARY }, { KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 35 */
  	{ KNOT_RRTYPE_NAPTR, "NAPTR", 6,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_TEXT_SINGLE,
	    KNOT_RDATA_WF_TEXT_SINGLE, KNOT_RDATA_WF_TEXT_SINGLE,
	    KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_TEXT, KNOT_RDATA_ZF_TEXT,
	    KNOT_RDATA_ZF_TEXT, KNOT_RDATA_ZF_DNAME }, true },
  	/* 36 */
  	{ KNOT_RRTYPE_KX, "KX", 2,
  	  { KNOT_RDATA_WF_SHORT,
	    KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_DNAME }, true },
  	/* 37 */
  	{ KNOT_RRTYPE_CERT, "CERT", 4,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_SHORT,
	    KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_CERTIFICATE_TYPE, KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_ALGORITHM,
	    KNOT_RDATA_ZF_BASE64 }, true },
  	/* 38 */
  	{ KNOT_RRTYPE_A6, NULL, 1, { KNOT_RDATA_WF_BINARY },
	{ KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 39 */
  	{ KNOT_RRTYPE_DNAME, "DNAME", 1,
  	  { KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
	  { KNOT_RDATA_ZF_DNAME }, true },
  	/* 40 */
  	{ 40, NULL, 1, { KNOT_RDATA_WF_BINARY },
	{ KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 41 */
	/* OPT has its parser token, but should never be in zone file... */
  	{ KNOT_RRTYPE_OPT, "OPT", 1,
  	  { KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_UNKNOWN }, true },
  	/* 42 */
	{ KNOT_RRTYPE_APL, "APL", 64,
	         { KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL,
	           KNOT_RDATA_WF_APL, KNOT_RDATA_WF_APL },
          { KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL,
            KNOT_RDATA_ZF_APL, KNOT_RDATA_ZF_APL }, 
          false },
  	/* 43 */
  	{ KNOT_RRTYPE_DS, "DS", 4,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_BYTE,
	  KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BINARY },
  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_ALGORITHM, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_HEX }, true },
  	/* 44 */
  	{ KNOT_RRTYPE_SSHFP, "SSHFP", 3,
  	  { KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BYTE,
	    KNOT_RDATA_WF_BINARY },
	    { KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_HEX },
	      true },
  	/* 45 */
  	{ KNOT_RRTYPE_IPSECKEY, "IPSECKEY", 5,
  	  { KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BYTE,
	    KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_IPSECGATEWAY,
  	    KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_IPSECGATEWAY,
	    KNOT_RDATA_ZF_BASE64 }, false },
  	/* 46 */
  	{ KNOT_RRTYPE_RRSIG, "RRSIG", 9,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_BYTE,
	    KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_LONG,
  	    KNOT_RDATA_WF_LONG, KNOT_RDATA_WF_LONG,
	    KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_LITERAL_DNAME,
	    KNOT_RDATA_WF_BINARY },
	    { KNOT_RDATA_ZF_RRTYPE, KNOT_RDATA_ZF_ALGORITHM,
              KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_PERIOD,
              KNOT_RDATA_ZF_TIME, KNOT_RDATA_ZF_TIME,
              KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_LITERAL_DNAME,
              KNOT_RDATA_ZF_BASE64 }, true },
  	/* 47 */
  	{ KNOT_RRTYPE_NSEC, "NSEC", 2,
	  { KNOT_RDATA_WF_LITERAL_DNAME, KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_LITERAL_DNAME, KNOT_RDATA_ZF_NSEC },
	  true },
  	/* 48 */
  	{ KNOT_RRTYPE_DNSKEY, "DNSKEY", 4,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_BYTE,
	    KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BINARY },
	  { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_BYTE,
            KNOT_RDATA_ZF_ALGORITHM, KNOT_RDATA_ZF_BASE64 }, true },
  	/* 49 */
  	{ KNOT_RRTYPE_DHCID, "DHCID", 1, { KNOT_RDATA_WF_BINARY },
	{ KNOT_RDATA_ZF_BASE64 }, true },
  	/* 50 */
  	{ KNOT_RRTYPE_NSEC3, "NSEC3", 6,
  	  { KNOT_RDATA_WF_BYTE, /* hash type */
  	    KNOT_RDATA_WF_BYTE, /* flags */
  	    KNOT_RDATA_WF_SHORT, /* iterations */
  	    KNOT_RDATA_WF_BINARYWITHLENGTH, /* salt */
	    KNOT_RDATA_WF_BINARYWITHLENGTH, /* next hashed name */
  	    KNOT_RDATA_WF_BINARY /* type bitmap */ },
	  { KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_HEX_LEN,
	    KNOT_RDATA_ZF_BASE32, KNOT_RDATA_ZF_NSEC },
	    true },
  	/* 51 */
  	{ KNOT_RRTYPE_NSEC3PARAM, "NSEC3PARAM", 4,
  	  { KNOT_RDATA_WF_BYTE, /* hash type */
  	    KNOT_RDATA_WF_BYTE, /* flags */
  	    KNOT_RDATA_WF_SHORT, /* iterations */
  	    KNOT_RDATA_WF_BINARYWITHLENGTH /* salt */ },
	  { KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_BYTE,
	    KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_HEX_LEN }, true },
  	/* 52 */


    /* In NSD they have indices between 52 and 99 filled with
     unknown types. TODO add here if it's really needed? */
     /* it is indeed needed, in rrtype_from_string */

    /* There's a GNU extension that works like this: [first ... last] = value */

  	/* 99 */
	[99] = { KNOT_RRTYPE_SPF, "SPF", 1,
  	  { KNOT_RDATA_WF_TEXT },
          { KNOT_RDATA_ZF_TEXT }, false },
        /* TSIG pseudo RR. */
        [250] = { KNOT_RRTYPE_TSIG, "TSIG", 7,
		 { KNOT_RDATA_WF_UNCOMPRESSED_DNAME, KNOT_RDATA_WF_UINT48,
                   KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_BINARYWITHSHORT,
                   KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_SHORT,
                   KNOT_RDATA_WF_BINARYWITHSHORT },
                  /* Zoneformat not needed. */
                  {0, 0, 0, 0, 0}, true },
  	/* 32769 */
  	[32769] = { KNOT_RRTYPE_DLV, "DLV", 4,
  	  { KNOT_RDATA_WF_SHORT, KNOT_RDATA_WF_BYTE,
	    KNOT_RDATA_WF_BYTE, KNOT_RDATA_WF_BINARY },
	    { KNOT_RDATA_ZF_SHORT, KNOT_RDATA_ZF_ALGORITHM, KNOT_RDATA_ZF_BYTE, KNOT_RDATA_ZF_HEX },
	    true },
};

knot_rrtype_descriptor_t *knot_rrtype_descriptor_by_type(uint16_t type)
{
	if (type < KNOT_RRTYPE_LAST + 1) {
		return &knot_rrtype_descriptors[type];
	} else if (type == KNOT_RRTYPE_DLV) {
		return &knot_rrtype_descriptors[KNOT_RRTYPE_DLV];
	}
	return &knot_rrtype_descriptors[0];
}

/* I see a lot of potential here to speed up zone parsing - this is O(n) *
 * could be better */
knot_rrtype_descriptor_t *knot_rrtype_descriptor_by_name(const char *name)
{
	int i;

	for (i = 0; i < KNOT_RRTYPE_DLV + 1; ++i) {
		if (knot_rrtype_descriptors[i].name &&
		    strcasecmp(knot_rrtype_descriptors[i].name, name) == 0) {
			return &knot_rrtype_descriptors[i];
		}
	}

	if (knot_rrtype_descriptors[KNOT_RRTYPE_DLV].name &&
	    strcasecmp(knot_rrtype_descriptors[KNOT_RRTYPE_DLV].name,
	                              name) == 0) {
		return &knot_rrtype_descriptors[KNOT_RRTYPE_DLV];
	}

	return NULL;
}

const char *knot_rrtype_to_string(uint16_t rrtype)
{
	static char buf[20];
	knot_rrtype_descriptor_t *descriptor =
	        knot_rrtype_descriptor_by_type(rrtype);
	if (descriptor->name) {
		return descriptor->name;
	} else {
		snprintf(buf, sizeof(buf), "TYPE%d", (int) rrtype);
		return buf;
	}
}

uint16_t knot_rrtype_from_string(const char *name)
{
	char *end;
	long rrtype;
	knot_rrtype_descriptor_t *entry;

	entry = knot_rrtype_descriptor_by_name(name);
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

const char *knot_rrclass_to_string(uint16_t rrclass)
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

uint16_t knot_rrclass_from_string(const char *name)
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

size_t knot_wireformat_size(unsigned int wire_type)
{
	switch(wire_type) {
		case KNOT_RDATA_WF_BYTE:
			return 1;
			break;
		case KNOT_RDATA_WF_SHORT:
			return 2;
			break;
		case KNOT_RDATA_WF_LONG:
			return 4;
			break;
		case KNOT_RDATA_WF_A:
			return 4;
			break;
		default: /* unknown size */
			return 0;
			break;
	} /* switch */
}

int knot_rrtype_is_metatype(uint16_t type)
{
	/*! \todo Check if there are some other metatypes. */
	return (type == KNOT_RRTYPE_ANY
	        || type == KNOT_RRTYPE_AXFR
	        || type == KNOT_RRTYPE_IXFR
	        || type == KNOT_RRTYPE_MAILA
	        || type == KNOT_RRTYPE_MAILB
	        || type == KNOT_RRTYPE_OPT);
}

