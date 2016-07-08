/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief Some DNS-related constants.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

/*!
 * \brief Basic limits for domain names (RFC 1035).
 */
#define KNOT_DNAME_MAXLEN      255 /*!< 1-byte maximum. */
#define KNOT_DNAME_MAXLABELS   127 /*!< 1-char labels. */
#define KNOT_DNAME_MAXLABELLEN  63 /*!< 2^6 - 1 */

/*!
 * \brief The longest textual dname representation.
 *
 * 3 x maximum_label + 1 x rest_label + 1 x zero_label
 * Each dname label byte takes 4 characters (\DDD).
 * Each label takes 1 more byte for '.' character.
 *
 * KNOT_DNAME_TXT_MAXLEN = 3x(1 + 63x4) + 1x(1 + 61x4) + 1x(1 + 0)
 */
#define KNOT_DNAME_TXT_MAXLEN 1005

/*!
 * \brief Address family numbers.
 *
 * http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml
 */
typedef enum {
	KNOT_ADDR_FAMILY_IPV4 = 1, /*!< IP version 4. */
	KNOT_ADDR_FAMILY_IPV6 = 2  /*!< IP version 6. */
} knot_addr_family_t;

/*!
 * \brief DNS operation codes (OPCODEs).
 *
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
 */
typedef enum {
	KNOT_OPCODE_QUERY  = 0, /*!< Standard query. */
	KNOT_OPCODE_IQUERY = 1, /*!< Inverse query. */
	KNOT_OPCODE_STATUS = 2, /*!< Server status request. */
	KNOT_OPCODE_NOTIFY = 4, /*!< Notify message. */
	KNOT_OPCODE_UPDATE = 5  /*!< Dynamic update. */
} knot_opcode_t;

/*!
 * \brief DNS reply codes (RCODEs).
 *
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
 *
 * \note Here, only RCODEs present in Header or as an Extended RCODE in
 *       OPT + Header are listed. Other codes are used in dedicated fields of
 *       other RRs.
 */
typedef enum {
	KNOT_RCODE_NOERROR   =  0, /*!< No error. */
	KNOT_RCODE_FORMERR   =  1, /*!< Format error. */
	KNOT_RCODE_SERVFAIL  =  2, /*!< Server failure. */
	KNOT_RCODE_NXDOMAIN  =  3, /*!< Non-existent domain. */
	KNOT_RCODE_NOTIMPL   =  4, /*!< Not implemented. */
	KNOT_RCODE_REFUSED   =  5, /*!< Refused. */
	KNOT_RCODE_YXDOMAIN  =  6, /*!< Name should not exist. */
	KNOT_RCODE_YXRRSET   =  7, /*!< RR set should not exist. */
	KNOT_RCODE_NXRRSET   =  8, /*!< RR set does not exist. */
	KNOT_RCODE_NOTAUTH   =  9, /*!< Server not authoritative. / Query not authorized. */
	KNOT_RCODE_NOTZONE   = 10, /*!< Name is not inside zone. */
	KNOT_RCODE_BADVERS   = 16, /*!< Bad OPT Version. */
	KNOT_RCODE_BADCOOKIE = 23  /*!< Bad/missing server cookie. */
} knot_rcode_t;

/*!
 * \brief TSIG error codes to be set in the TSIG RR's RDATA.
 *
 * Defined in RFC 2845 and RFC 4635.
 * See also https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
 */
typedef enum {
	KNOT_TSIG_ERR_BADSIG   = 16, /*!< TSIG signature failed. */
	KNOT_TSIG_ERR_BADKEY   = 17, /*!< Key is not supported. */
	KNOT_TSIG_ERR_BADTIME  = 18, /*!< Signature out of time window. */
	KNOT_TSIG_ERR_BADTRUNC = 22  /*!< Bad truncation. */
} knot_tsig_error_t;

/*!
 * \brief TKEY error codes. (Defined in RFC 2930.)
 */
typedef enum {
	KNOT_TKEY_ERR_BADMODE  = 19, /*!< Bad TKEY mode. */
	KNOT_TKEY_ERR_BADNAME  = 20, /*!< Duplicate key name. */
	KNOT_TKEY_ERR_BADALG   = 21  /*!< Algorithm not supported. */
} knot_tkey_error_t;

/*!
 * \brief DNS packet section identifiers.
 */
typedef enum {
	KNOT_ANSWER       = 0,
	KNOT_AUTHORITY    = 1,
	KNOT_ADDITIONAL   = 2
} knot_section_t;

/*!
 * \brief DS digest lengths.
 */
enum knot_ds_algorithm_len
{
	KNOT_DS_DIGEST_LEN_SHA1   = 20, /*!< RFC 3658 */
	KNOT_DS_DIGEST_LEN_SHA256 = 32, /*!< RFC 4509 */
	KNOT_DS_DIGEST_LEN_GOST   = 32, /*!< RFC 5933 */
	KNOT_DS_DIGEST_LEN_SHA384 = 48  /*!< RFC 6605 */
};

/*!
 * \brief Constants for DNSSEC algorithm types.
 *
 * Source: http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xml
 */
typedef enum {
	KNOT_DS_ALG_SHA1   = 1,
	KNOT_DS_ALG_SHA256 = 2,
	KNOT_DS_ALG_GOST   = 3,
	KNOT_DS_ALG_SHA384 = 4
} knot_ds_algorithm_t;

/*!
 * \brief DNSSEC algorithm numbers.
 *
 * http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
 */
typedef enum {
	KNOT_DNSSEC_ALG_RSAMD5             =   1,
	KNOT_DNSSEC_ALG_DH                 =   2,
	KNOT_DNSSEC_ALG_DSA                =   3,

	KNOT_DNSSEC_ALG_RSASHA1            =   5,
	KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1     =   6,
	KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1 =   7,
	KNOT_DNSSEC_ALG_RSASHA256          =   8,

	KNOT_DNSSEC_ALG_RSASHA512          =  10,

	KNOT_DNSSEC_ALG_ECC_GOST           =  12,
	KNOT_DNSSEC_ALG_ECDSAP256SHA256    =  13,
	KNOT_DNSSEC_ALG_ECDSAP384SHA384    =  14,

	KNOT_DNSSEC_ALG_INDIRECT           = 252,
	KNOT_DNSSEC_ALG_PRIVATEDNS         = 253,
	KNOT_DNSSEC_ALG_PRIVATEOID         = 254
} knot_dnssec_algorithm_t;

/*!
 * \brief NSEC3 hash algorithm numbers.
 */
typedef enum {
	KNOT_NSEC3_ALGORITHM_SHA1 = 1
} knot_nsec3_hash_algorithm_t;

/*! @} */
