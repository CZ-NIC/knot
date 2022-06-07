/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
 * Binary:  3 x (0x3F + maximum_label) + (0x3D + rest_label) + (0x00)
 * Textual: 3 x (maximum_label + '.') + (rest_label + '.')
 *
 * Each dname label byte takes 4 characters (\\DDD).
 *
 * KNOT_DNAME_TXT_MAXLEN = 3 x (63 x 4 + 1) + (61 x 4 + 1)
 */
#define KNOT_DNAME_TXT_MAXLEN 1004

/*!
 * \brief Address family numbers.
 *
 * https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml
 */
typedef enum {
	KNOT_ADDR_FAMILY_IPV4 = 1, /*!< IP version 4. */
	KNOT_ADDR_FAMILY_IPV6 = 2  /*!< IP version 6. */
} knot_addr_family_t;

/*!
 * \brief DNS operation codes (OPCODEs).
 *
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xml
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
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xml
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
	KNOT_RCODE_BADSIG    = 16, /*!< (TSIG) Signature failure. */
	KNOT_RCODE_BADKEY    = 17, /*!< (TSIG) Key is not supported. */
	KNOT_RCODE_BADTIME   = 18, /*!< (TSIG) Signature out of time window. */
	KNOT_RCODE_BADMODE   = 19, /*!< (TKEY) Bad mode. */
	KNOT_RCODE_BADNAME   = 20, /*!< (TKEY) Duplicate key name. */
	KNOT_RCODE_BADALG    = 21, /*!< (TKEY) Algorithm not supported. */
	KNOT_RCODE_BADTRUNC  = 22, /*!< (TSIG) Bad truncation. */
	KNOT_RCODE_BADCOOKIE = 23  /*!< Bad/missing server cookie. */
} knot_rcode_t;

/*!
 * \brief Extended error codes as in EDNS option #15.
 *
 * \note The default -1 value must be filtered out before storing to uint16_t!
 *
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xml#extended-dns-error-codes
 */
typedef enum {
	KNOT_EDNS_EDE_NONE             = -1,
	KNOT_EDNS_EDE_OTHER            = 0,
	KNOT_EDNS_EDE_DNSKEY_ALG       = 1,
	KNOT_EDNS_EDE_DS_DIGEST        = 2,
	KNOT_EDNS_EDE_STALE            = 3,
	KNOT_EDNS_EDE_FORGED           = 4,
	KNOT_EDNS_EDE_INDETERMINATE    = 5,
	KNOT_EDNS_EDE_BOGUS            = 6,
	KNOT_EDNS_EDE_SIG_EXPIRED      = 7,
	KNOT_EDNS_EDE_SIG_NOTYET       = 8,
	KNOT_EDNS_EDE_DNSKEY_MISS      = 9,
	KNOT_EDNS_EDE_RRSIG_MISS       = 10,
	KNOT_EDNS_EDE_DNSKEY_BIT       = 11,
	KNOT_EDNS_EDE_NSEC_MISS        = 12,
	KNOT_EDNS_EDE_CACHED_ERR       = 13,
	KNOT_EDNS_EDE_NOT_READY        = 14,
	KNOT_EDNS_EDE_BLOCKED          = 15,
	KNOT_EDNS_EDE_CENSORED         = 16,
	KNOT_EDNS_EDE_FILTERED         = 17,
	KNOT_EDNS_EDE_PROHIBITED       = 18,
	KNOT_EDNS_EDE_STALE_NXD        = 19,
	KNOT_EDNS_EDE_NOTAUTH          = 20,
	KNOT_EDNS_EDE_NOTSUP           = 21,
	KNOT_EDNS_EDE_NREACH_AUTH      = 22,
	KNOT_EDNS_EDE_NETWORK          = 23,
	KNOT_EDNS_EDE_INV_DATA         = 24,
	KNOT_EDNS_EDE_EXPIRED_INV      = 25,
	KNOT_EDNS_EDE_TOO_EARLY        = 26,
	KNOT_EDNS_EDE_NSEC3_ITERS      = 27,
} knot_edns_ede_t;

/*!
 * \brief DNS packet section identifiers.
 */
typedef enum {
	KNOT_ANSWER       = 0,
	KNOT_AUTHORITY    = 1,
	KNOT_ADDITIONAL   = 2
} knot_section_t;

/*!
 * \brief Service Binding (SVCB) Parameter Registry
 *
 * https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-05 // FIXME
 */
typedef enum {
	KNOT_SVCB_PARAM_MANDATORY = 0,
	KNOT_SVCB_PARAM_ALPN      = 1,
	KNOT_SVCB_PARAM_NDALPN    = 2,
	KNOT_SVCB_PARAM_PORT      = 3,
	KNOT_SVCB_PARAM_IPV4HINT  = 4,
	KNOT_SVCB_PARAM_ECH       = 5,
	KNOT_SVCB_PARAM_IPV6HINT  = 6,
} knot_svcb_param_t;

/*! @} */
