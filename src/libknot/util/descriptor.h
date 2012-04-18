/*!
 * \file descriptor.h
 *
 * \author Modifications by Jan Kadlec <jan.kadlec@nic.cz>,
 *         most of the work by NLnet Labs.
 *         Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * \note Most of the constants and functions were taken from NSD's dns.h.
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

#ifndef _KNOT_DESCRIPTOR_H_
#define _KNOT_DESCRIPTOR_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

enum knot_mxrdtln {
	/*! \brief Maximum items in RDATA wireformat. */
	KNOT_MAX_RDATA_ITEMS = 64,
	/*! \brief Maximum size of one item in RDATA wireformat. */
	KNOT_MAX_RDATA_ITEM_SIZE = 65534,
	/*! \brief Maximum wire size of one RDATA. */
	KNOT_MAX_RDATA_WIRE_SIZE =
	KNOT_MAX_RDATA_ITEMS * KNOT_MAX_RDATA_ITEM_SIZE
};

typedef enum knot_mxrdtln knot_mxrdtln_t;
//#define MAXRDATALEN 64

/* 64 is in NSD. Seems a little too much, but I'd say it's not a real issue. */

/*!
 * \brief Resource record class codes.
 */
enum knot_rr_class {
	KNOT_CLASS_IN = 1,
	KNOT_CLASS_CS,
	KNOT_CLASS_CH,
	KNOT_CLASS_HS,
	KNOT_CLASS_NONE = 254,
	KNOT_CLASS_ANY = 255
};

typedef enum knot_rr_class knot_rr_class_t;

/*!
 * \brief Resource record type constants.
 * \todo Not all indices can be used for indexing.
 */
enum knot_rr_type {
	KNOT_RRTYPE_UNKNOWN, /*!< 0 - an unknown type */
	KNOT_RRTYPE_A, /*!< 1 - a host address */
	KNOT_RRTYPE_NS, /*!< 2 - an authoritative name server */
	KNOT_RRTYPE_MD, /*!< 3 - a mail destination (Obsolete - use MX) */
	KNOT_RRTYPE_MF, /*!< 4 - a mail forwarder (Obsolete - use MX) */
	KNOT_RRTYPE_CNAME, /*!< 5 - the canonical name for an alias */
	KNOT_RRTYPE_SOA, /*!< 6 - marks the start of a zone of authority */
	KNOT_RRTYPE_MB, /*!< 7 - a mailbox domain name (EXPERIMENTAL) */
	KNOT_RRTYPE_MG, /*!< 8 - a mail group member (EXPERIMENTAL) */
	KNOT_RRTYPE_MR, /*!< 9 - a mail rename domain name (EXPERIMENTAL) */
	KNOT_RRTYPE_NULL, /*!< 10 - a null RR (EXPERIMENTAL) */
	KNOT_RRTYPE_WKS, /*!< 11 - a well known service description */
	KNOT_RRTYPE_PTR, /*!< 12 - a domain name pointer */
	KNOT_RRTYPE_HINFO, /*!< 13 - host information */
	KNOT_RRTYPE_MINFO, /*!< 14 - mailbox or mail list information */
	KNOT_RRTYPE_MX, /*!< 15 - mail exchange */
	KNOT_RRTYPE_TXT, /*!< 16 - text strings */
	KNOT_RRTYPE_RP, /*!< 17 - RFC1183 */
	KNOT_RRTYPE_AFSDB, /*!< 18 - RFC1183 */
	KNOT_RRTYPE_X25, /*!< 19 - RFC1183 */
	KNOT_RRTYPE_ISDN, /*!< 20 - RFC1183 */
	KNOT_RRTYPE_RT, /*!< 21 - RFC1183 */
	KNOT_RRTYPE_NSAP, /*!< 22 - RFC1706 */

	KNOT_RRTYPE_SIG = 24, /*!< 24 - 2535typecode */
	KNOT_RRTYPE_KEY, /*!< 25 - 2535typecode */
	KNOT_RRTYPE_PX, /*!< 26 - RFC2163 */

	KNOT_RRTYPE_AAAA = 28, /*!< 28 - ipv6 address */
	KNOT_RRTYPE_LOC, /*!< 29 - LOC record  RFC1876 */
	KNOT_RRTYPE_NXT, /*!< 30 - 2535typecode */

	KNOT_RRTYPE_SRV = 33, /*!< 33 - SRV record RFC2782 */

	KNOT_RRTYPE_NAPTR = 35, /*!< 35 - RFC2915 */
	KNOT_RRTYPE_KX, /*!< 36 - RFC2230 Key Exchange Delegation Record */
	KNOT_RRTYPE_CERT, /*!< 37 - RFC2538 */
	KNOT_RRTYPE_A6, /*!< 38 - RFC2874 */
	KNOT_RRTYPE_DNAME, /*!< 39 - RFC2672 */

	KNOT_RRTYPE_OPT = 41, /*!< 41 - Pseudo OPT record... */
	KNOT_RRTYPE_APL, /*!< 42 - RFC3123 */
	KNOT_RRTYPE_DS, /*!< 43 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_SSHFP, /*!< 44 - SSH Key Fingerprint */
	KNOT_RRTYPE_IPSECKEY, /*!< 45 - public key for ipsec use. RFC 4025 */
	KNOT_RRTYPE_RRSIG, /*!< 46 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_NSEC, /*!< 47 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_DNSKEY, /*!< 48 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_DHCID, /*!< 49 - RFC4701 DHCP information */
	/*!
	 * \brief 50 - NSEC3, secure denial, prevents zonewalking
	 */
	KNOT_RRTYPE_NSEC3,
	/*!
	 * \brief  51 - NSEC3PARAM at zone apex nsec3 parameters
	 */
	KNOT_RRTYPE_NSEC3PARAM, 
	KNOT_RRTYPE_TLSA = 52,

	/* TODO consider some better way of doing this, indices too high */

	KNOT_RRTYPE_SPF = 99,      /*!< RFC 4408 */

	// not designating any RRs
	KNOT_RRTYPE_TSIG = 250, /*!< TSIG - RFC2845. */
	KNOT_RRTYPE_IXFR = 251, /*!< IXFR (not an actual RR). */
	KNOT_RRTYPE_AXFR = 252, /*!< AXFR (not an actual RR). */
	/*!
	 * \brief A request for mailbox-related records (MB, MG or MR)
	 */
	KNOT_RRTYPE_MAILB = 253,
	/*!
	 * \brief A request for mail agent RRs (Obsolete - see MX)
	 */
	KNOT_RRTYPE_MAILA = 254,
	KNOT_RRTYPE_ANY = 255, /*!< any type (wildcard) */

	// totally weird numbers (cannot use for indexing)
	KNOT_RRTYPE_TA = 32768, /*!< DNSSEC Trust Authorities */
	KNOT_RRTYPE_DLV = 32769, /*!< RFC 4431 */

	/*! \brief Last normal RR type. */
	KNOT_RRTYPE_LAST = KNOT_RRTYPE_TSIG
	/*! \todo [TSIG] Is it allright to include all <= RR TSIG?
	 * Because TSIG is normal RR type. */
};

typedef enum knot_rr_type knot_rr_type_t;

/*! \brief Constants characterising the wire format of RDATA items. */
enum knot_rdata_wireformat {
	/*!
	 * \brief Possibly compressed domain name.
	 */	
	KNOT_RDATA_WF_COMPRESSED_DNAME = 50,
	KNOT_RDATA_WF_UNCOMPRESSED_DNAME = 51, /*!< Uncompressed domain name.  */
	KNOT_RDATA_WF_LITERAL_DNAME = 52, /*!< Literal (not downcased) dname.  */
	KNOT_RDATA_WF_BYTE = 1, /*!< 8-bit integer.  */
	KNOT_RDATA_WF_SHORT = 2, /*!< 16-bit integer.  */
	KNOT_RDATA_WF_LONG = 4, /*!< 32-bit integer.  */
	KNOT_RDATA_WF_UINT48 = 8, /*!< 48-bit integer.  */
	KNOT_RDATA_WF_TEXT = 53, /*!< Text string.  */
	KNOT_RDATA_WF_A = 58, /*!< 32-bit IPv4 address.  */
	KNOT_RDATA_WF_AAAA = 16, /*!< 128-bit IPv6 address.  */
	KNOT_RDATA_WF_BINARY = 54, /*!< Binary data (unknown length).  */
	/*!
	 * \brief Binary data preceded by 1 byte length 
	 */
	KNOT_RDATA_WF_BINARYWITHLENGTH = 55,
	KNOT_RDATA_WF_APL = 56, /*!< APL data.  */
	KNOT_RDATA_WF_IPSECGATEWAY = 57, /*!< IPSECKEY gateway ip4, ip6 or dname. */
	KNOT_RDATA_WF_BINARYWITHSHORT = 59,
	KNOT_RDATA_WF_TEXT_SINGLE = 60 /*!< Text string. */
};

/*! \brief Constants characterising the format of RDATA items in zone file. */
enum knot_rdata_zoneformat
{
	KNOT_RDATA_ZF_DNAME,		/* Domain name.  */
	KNOT_RDATA_ZF_LITERAL_DNAME,	/* DNS name (not lowercased domain name).  */
	KNOT_RDATA_ZF_TEXT,		/* Text string.  */
	KNOT_RDATA_ZF_BYTE,		/* 8-bit integer.  */
	KNOT_RDATA_ZF_SHORT,		/* 16-bit integer.  */
	KNOT_RDATA_ZF_LONG,		/* 32-bit integer.  */
	KNOT_RDATA_ZF_A,		/* 32-bit IPv4 address.  */
	KNOT_RDATA_ZF_AAAA,		/* 128-bit IPv6 address.  */
	KNOT_RDATA_ZF_RRTYPE,		/* RR type.  */
	KNOT_RDATA_ZF_ALGORITHM,	/* Cryptographic algorithm.  */
	KNOT_RDATA_ZF_CERTIFICATE_TYPE,
	KNOT_RDATA_ZF_PERIOD,		/* Time period.  */
	KNOT_RDATA_ZF_TIME,
	KNOT_RDATA_ZF_BASE64,		/* Base-64 binary data.  */
	KNOT_RDATA_ZF_BASE32,		/* Base-32 binary data.  */
	KNOT_RDATA_ZF_HEX,		/* Hexadecimal binary data.  */
	KNOT_RDATA_ZF_HEX_LEN,	/* Hexadecimal binary data. Skip initial length byte. */
	KNOT_RDATA_ZF_NSAP,		/* NSAP.  */
	KNOT_RDATA_ZF_APL,		/* APL.  */
	KNOT_RDATA_ZF_IPSECGATEWAY,	/* IPSECKEY gateway ip4, ip6 or dname. */
	KNOT_RDATA_ZF_SERVICES,	/* Protocol and port number bitmap.  */
	KNOT_RDATA_ZF_NXT,		/* NXT type bitmap.  */
	KNOT_RDATA_ZF_NSEC,		/* NSEC type bitmap.  */
	KNOT_RDATA_ZF_LOC,		/* Location data.  */
	KNOT_RDATA_ZF_UNKNOWN	/* Unknown data.  */
};

/*! \brief Constants characterising the wire format of RDATA items. */
typedef enum knot_rdata_zoneformat knot_rdata_zoneformat_t;

/*! \brief Enum containing wireformat codes. */
typedef enum knot_rdatawireformat knot_rdata_wireformat_t;

/*! \brief Structure holding RR descriptor. */
struct knot_rrtype_descriptor {
	uint16_t type;          /*!< RR type */
	const char *name;       /*!< Textual name.  */
	uint8_t length;         /*!< Maximum number of RDATA items.  */

	/*! \brief Wire format specification for the RDATA. */
	uint8_t wireformat[KNOT_MAX_RDATA_ITEMS];

	/*! \brief Zone file format specification for the RDATA. */
	uint8_t zoneformat[KNOT_MAX_RDATA_ITEMS];

	bool fixed_items; /*!< Has fixed number of RDATA items? */
};

/*! \brief Structure holding RR descriptor. */
typedef struct knot_rrtype_descriptor knot_rrtype_descriptor_t;

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
knot_rrtype_descriptor_t *knot_rrtype_descriptor_by_type(uint16_t type);

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
knot_rrtype_descriptor_t *knot_rrtype_descriptor_by_name(const char *name);

/*!
 * \brief Converts numeric type representation to mnemonic string.
 *
 * \param rrtype Type RR type code to be converted.
 *
 * \return Mnemonic string if found, str(TYPE[rrtype]) otherwise.
 */
const char *knot_rrtype_to_string(uint16_t rrtype);

/*!
 * \brief Converts mnemonic string representation of a type to numeric one.
 *
 * \param name Mnemonic string to be converted.
 *
 * \return Correct code if found, 0 otherwise.
 */
uint16_t knot_rrtype_from_string(const char *name);

/*!
 * \brief Converts numeric class representation to string one.
 *
 * \param rrclass Class code to be converted.
 *
 * \return String represenation of class if found,
 *         str(CLASS[rrclass]) otherwise.
 */
const char *knot_rrclass_to_string(uint16_t rrclass);

/*!
 * \brief Converts string representation of a class to numeric one.
 *
 * \param name Class string to be converted.
 *
 * \return Correct code if found, 0 otherwise.
 */
uint16_t knot_rrclass_from_string(const char *name);

/*!
 * \brief Returns size of wireformat type in bytes.
 *
 * \param wire_type Wireformat type.
 *
 * \retval Size of given type on success.
 * \retval 0 on unknown type or type that has no length.
 */
size_t knot_wireformat_size(unsigned int wire_type);

int knot_rrtype_is_metatype(uint16_t type);

#endif /* _KNOT_DESCRIPTOR_H_ */

/*! @} */

