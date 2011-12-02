/*!
 * \file parser-descriptor.h
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

#ifndef _KNOTD_PARSER_DESCRIPTOR_H_
#define _KNOTD_PARSER_DESCRIPTOR_H_

#include <stdint.h>
#include <stdbool.h>

#include "libknot/util/utils.h"

enum parser_mxrdtln {
	PARSER_MAX_RDATA_ITEMS = 64,
	PARSER_MAX_RDATA_ITEM_SIZE = 255,
	PARSER_MAX_RDATA_WIRE_SIZE =
	PARSER_MAX_RDATA_ITEMS * PARSER_MAX_RDATA_ITEM_SIZE
};
//#define MAXRDATALEN 64

/* 64 is in NSD. Seems a little too much, but I'd say it's not a real issue. */

/*!
 * \brief Enum containing RR class codes.
 */
enum parser_rr_class {
	PARSER_CLASS_IN = 1,
	PARSER_CLASS_CS,
	PARSER_CLASS_CH,
	PARSER_CLASS_HS,
	PARSER_CLASS_NONE = 254,
	PARSER_CLASS_ANY = 255
};

typedef enum parser_rr_class parser_rr_class_t;

enum parser_rr_type {
	PARSER_RRTYPE_UNKNOWN, /*!< 0 - an unknown type */
	PARSER_RRTYPE_A, /*!< 1 - a host address */
	PARSER_RRTYPE_NS, /*!< 2 - an authoritative name server */
	PARSER_RRTYPE_MD, /*!< 3 - a mail destination (Obsolete - use MX) */
	PARSER_RRTYPE_MF, /*!< 4 - a mail forwarder (Obsolete - use MX) */
	PARSER_RRTYPE_CNAME, /*!< 5 - the canonical name for an alias */
	PARSER_RRTYPE_SOA, /*!< 6 - marks the start of a zone of authority */
	PARSER_RRTYPE_MB, /*!< 7 - a mailbox domain name (EXPERIMENTAL) */
	PARSER_RRTYPE_MG, /*!< 8 - a mail group member (EXPERIMENTAL) */
	PARSER_RRTYPE_MR, /*!< 9 - a mail rename domain name (EXPERIMENTAL) */
	PARSER_RRTYPE_NULL, /*!< 10 - a null RR (EXPERIMENTAL) */
	PARSER_RRTYPE_WKS, /*!< 11 - a well known service description */
	PARSER_RRTYPE_PTR, /*!< 12 - a domain name pointer */
	PARSER_RRTYPE_HINFO, /*!< 13 - host information */
	PARSER_RRTYPE_MINFO, /*!< 14 - mailbox or mail list information */
	PARSER_RRTYPE_MX, /*!< 15 - mail exchange */
	PARSER_RRTYPE_TXT, /*!< 16 - text strings */
	PARSER_RRTYPE_RP, /*!< 17 - RFC1183 */
	PARSER_RRTYPE_AFSDB, /*!< 18 - RFC1183 */
	PARSER_RRTYPE_X25, /*!< 19 - RFC1183 */
	PARSER_RRTYPE_ISDN, /*!< 20 - RFC1183 */
	PARSER_RRTYPE_RT, /*!< 21 - RFC1183 */
	PARSER_RRTYPE_NSAP, /*!< 22 - RFC1706 */

	PARSER_RRTYPE_SIG = 24, /*!< 24 - 2535typecode */
	PARSER_RRTYPE_KEY, /*!< 25 - 2535typecode */
	PARSER_RRTYPE_PX, /*!< 26 - RFC2163 */

	PARSER_RRTYPE_AAAA = 28, /*!< 28 - ipv6 address */
	PARSER_RRTYPE_LOC, /*!< 29 - LOC record  RFC1876 */
	PARSER_RRTYPE_NXT, /*!< 30 - 2535typecode */

	PARSER_RRTYPE_SRV = 33, /*!< 33 - SRV record RFC2782 */

	PARSER_RRTYPE_NAPTR = 35, /*!< 35 - RFC2915 */
	PARSER_RRTYPE_KX, /*!< 36 - RFC2230 Key Exchange Delegation Record */
	PARSER_RRTYPE_CERT, /*!< 37 - RFC2538 */
	PARSER_RRTYPE_A6, /*!< 38 - RFC2874 */
	PARSER_RRTYPE_DNAME, /*!< 39 - RFC2672 */

	PARSER_RRTYPE_OPT = 41, /*!< 41 - Pseudo OPT record... */
	PARSER_RRTYPE_APL, /*!< 42 - RFC3123 */
	PARSER_RRTYPE_DS, /*!< 43 - RFC 4033, 4034, and 4035 */
	PARSER_RRTYPE_SSHFP, /*!< 44 - SSH Key Fingerprint */
	PARSER_RRTYPE_IPSECKEY, /*!< 45 - public key for ipsec use. RFC 4025 */
	PARSER_RRTYPE_RRSIG, /*!< 46 - RFC 4033, 4034, and 4035 */
	PARSER_RRTYPE_NSEC, /*!< 47 - RFC 4033, 4034, and 4035 */
	PARSER_RRTYPE_DNSKEY, /*!< 48 - RFC 4033, 4034, and 4035 */
	PARSER_RRTYPE_DHCID, /*!< 49 - RFC4701 DHCP information */
	/*!
	 * \brief 50 - NSEC3, secure denial, prevents zonewalking
	 */
	PARSER_RRTYPE_NSEC3,
	/*!
	 * \brief  51 - NSEC3PARAM at zone apex nsec3 parameters
	 */
	PARSER_RRTYPE_NSEC3PARAM, 

	/* TODO consider some better way of doing this, indices too high */

	PARSER_RRTYPE_SPF = 99,      /*!< RFC 4408 */

	// not designating any RRs
	PARSER_RRTYPE_TSIG = 250,
	PARSER_RRTYPE_IXFR = 251,
	PARSER_RRTYPE_AXFR = 252,
	/*!
	 * \brief A request for mailbox-related records (MB, MG or MR)
	 */
	PARSER_RRTYPE_MAILB = 253,
	/*!
	 * \brief A request for mail agent RRs (Obsolete - see MX)
	 */
	PARSER_RRTYPE_MAILA = 254,
	PARSER_RRTYPE_ANY = 255, /*!< any type (wildcard) */

	// totally weird numbers (cannot use for indexing)
	PARSER_RRTYPE_TA = 32768, /*!< DNSSEC Trust Authorities */
	PARSER_RRTYPE_DLV = 32769, /*!< RFC 4431 */
	PARSER_RRTYPE_TYPEXXX = 32770
};

/*!
 * \brief Enum containing RR type codes.
 *
 * \todo Not all indices can be used for indexing.
 */
typedef enum parser_rr_type parser_rr_type_t;

static uint const PARSER_RRTYPE_LAST = PARSER_RRTYPE_SPF;

enum parser_rdata_wireformat {
	/*!
	 * \brief Possibly compressed domain name.
	 */	
	PARSER_RDATA_WF_COMPRESSED_DNAME = 50,
	PARSER_RDATA_WF_UNCOMPRESSED_DNAME = 51, /*!< Uncompressed domain name.  */
	PARSER_RDATA_WF_LITERAL_DNAME = 52, /*!< Literal (not downcased) dname.  */
	PARSER_RDATA_WF_BYTE = 1, /*!< 8-bit integer.  */
	PARSER_RDATA_WF_SHORT = 2, /*!< 16-bit integer.  */
	PARSER_RDATA_WF_LONG = 4, /*!< 32-bit integer.  */
	PARSER_RDATA_WF_TEXT = 53, /*!< Text string.  */
	PARSER_RDATA_WF_A = 58, /*!< 32-bit IPv4 address.  */
	PARSER_RDATA_WF_AAAA = 16, /*!< 128-bit IPv6 address.  */
	PARSER_RDATA_WF_BINARY = 54, /*!< Binary data (unknown length).  */
	/*!
	 * \brief Binary data preceded by 1 byte length 
	 */
	PARSER_RDATA_WF_BINARYWITHLENGTH = 55,
	PARSER_RDATA_WF_APL = 56, /*!< APL data.  */
	PARSER_RDATA_WF_IPSECGATEWAY = 57 /*!< IPSECKEY gateway ip4, ip6 or dname. */
};

/*!
 * \brief Enum containing wireformat codes. Taken from NSD's "dns.h"
 */
typedef enum parser_rdatawireformat parser_rdata_wireformat_t;

struct parser_rrtype_descriptor {
	uint16_t type;	/*!< RR type */
	int token; /*< Token used in zoneparser */
	const char *name;	/*!< Textual name.  */
	uint8_t length;	/*!< Maximum number of RDATA items.  */
	/*!
	 * \brief rdata_wireformat_type
	 */
	uint8_t wireformat[PARSER_MAX_RDATA_ITEMS]; 
	bool fixed_items; /*!< Has fixed number of RDATA items? */
};

/*!
 * \brief Structure holding RR descriptor
 */
typedef struct parser_rrtype_descriptor parser_rrtype_descriptor_t;

/*!
 * \brief Gets RR descriptor for given RR type.
 *
 * \param type Code of RR type whose descriptor should be returned.
 *
 * \return RR descriptor for given type code, NULL descriptor if
 *         unknown type.
 *
 * \todo Change return value to const.
 */
parser_rrtype_descriptor_t *parser_rrtype_descriptor_by_type(uint16_t type);

/*!
 * \brief Gets RR descriptor for given RR name.
 *
 * \param name Mnemonic of RR type whose descriptor should be returned.
 *
 * \return RR descriptor for given name, NULL descriptor if
 *         unknown type.
 *
 * \todo Change return value to const.
 */
parser_rrtype_descriptor_t *parser_rrtype_descriptor_by_name(const char *name);

/*!
 * \brief Converts numeric type representation to mnemonic string.
 *
 * \param rrtype Type RR type code to be converted.
 *
 * \return Mnemonic string if found, str(TYPE[rrtype]) otherwise.
 */
const char *parser_rrtype_to_string(uint16_t rrtype);

/*!
 * \brief Converts mnemonic string representation of a type to numeric one.
 *
 * \param name Mnemonic string to be converted.
 *
 * \return Correct code if found, 0 otherwise.
 */
uint16_t parser_rrtype_from_string(const char *name);

/*!
 * \brief Converts numeric class representation to string one.
 *
 * \param rrclass Class code to be converted.
 *
 * \return String represenation of class if found,
 *         str(CLASS[rrclass]) otherwise.
 */
const char *parser_rrclass_to_string(uint16_t rrclass);

/*!
 * \brief Converts string representation of a class to numeric one.
 *
 * \param name Class string to be converted.
 *
 * \return Correct code if found, 0 otherwise.
 */
uint16_t parser_rrclass_from_string(const char *name);

#endif /* _KNOTD_PARSER_DESCRIPTOR_H_ */

/*! @} */
