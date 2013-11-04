/*!
 * \file consts.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Contains some DNS-related constants.
 *
 * \addtogroup libknot
 * @{
 */
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

#ifndef _KNOT_CONSTS_H_
#define _KNOT_CONSTS_H_

#include <stdbool.h>
#include <stdint.h>

#include "libknot/util/utils.h"

/*!
 * \brief Basic limits for domain names (RFC 1035).
 */
#define KNOT_DNAME_MAXLEN 255     /*!< 1-byte maximum. */
#define KNOT_DNAME_MAXLABELS 127  /*!< 1-char labels. */

/*!
 * \brief Often used sizes.
 */
#define KNOT_RR_HEADER_SIZE 10

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
 */
typedef enum {
	KNOT_RCODE_NOERROR  =  0, /*!< No error. */
	KNOT_RCODE_FORMERR  =  1, /*!< Format error. */
	KNOT_RCODE_SERVFAIL =  2, /*!< Server failure. */
	KNOT_RCODE_NXDOMAIN =  3, /*!< Non-existend domain. */
	KNOT_RCODE_NOTIMPL  =  4, /*!< Not implemented. */
	KNOT_RCODE_REFUSED  =  5, /*!< Refused. */
	KNOT_RCODE_YXDOMAIN =  6, /*!< Name should not exist. */
	KNOT_RCODE_YXRRSET  =  7, /*!< RR set should not exist. */
	KNOT_RCODE_NXRRSET  =  8, /*!< RR set does not exist. */
	KNOT_RCODE_NOTAUTH  =  9, /*!< Server not authoritative. */
	KNOT_RCODE_NOTZONE  = 10, /*!< Name is not inside zone. */
	KNOT_RCODE_BADSIG   = 16, /*!< TSIG signature failed. */
	KNOT_RCODE_BADKEY   = 17, /*!< Key is not supported. */
	KNOT_RCODE_BADTIME  = 18, /*!< Signature out of time window. */
	KNOT_RCODE_BADMODE  = 19, /*!< Bad TKEY mode. */
	KNOT_RCODE_BADNAME  = 20, /*!< Duplicate key name. */
	KNOT_RCODE_BADALG   = 21, /*!< Algorithm not supported. */
	KNOT_RCODE_BADTRUNC = 22  /*!< Bad truncation. */
} knot_rcode_t;

/*!
 * \brief DNS query types (internal use only).
 *
 * This type encompasses the different query types distinguished by both the
 * OPCODE and the QTYPE.
 */
typedef enum {
	KNOT_QUERY_INVALID,   /*!< Invalid query. */
	KNOT_QUERY_NORMAL,    /*!< Normal query. */
	KNOT_QUERY_AXFR,      /*!< Request for AXFR transfer. */
	KNOT_QUERY_IXFR,      /*!< Request for IXFR transfer. */
	KNOT_QUERY_NOTIFY,    /*!< NOTIFY query. */
	KNOT_QUERY_UPDATE,    /*!< Dynamic update. */
	KNOT_RESPONSE_NORMAL, /*!< Normal response. */
	KNOT_RESPONSE_AXFR,   /*!< AXFR transfer response. */
	KNOT_RESPONSE_IXFR,   /*!< IXFR transfer response. */
	KNOT_RESPONSE_NOTIFY, /*!< NOTIFY response. */
	KNOT_RESPONSE_UPDATE  /*!< Dynamic update response. */
} knot_packet_type_t;

/*!
 * \brief TSIG algorithm numbers.
 *
 * These constants were taken from the Bind file key format (dnssec-keygen).
 */
typedef enum {
	KNOT_TSIG_ALG_NULL        =   0,
	KNOT_TSIG_ALG_GSS_TSIG    = 128,
	KNOT_TSIG_ALG_HMAC_MD5    = 157,
	KNOT_TSIG_ALG_HMAC_SHA1   = 161,
	KNOT_TSIG_ALG_HMAC_SHA224 = 162,
	KNOT_TSIG_ALG_HMAC_SHA256 = 163,
	KNOT_TSIG_ALG_HMAC_SHA384 = 164,
	KNOT_TSIG_ALG_HMAC_SHA512 = 165
} knot_tsig_algorithm_t;

/*!
 * \brief Lengths of TSIG algorithm digests.
 */
typedef enum {
	KNOT_TSIG_ALG_DIG_LENGTH_GSS_TSIG =  0,
	KNOT_TSIG_ALG_DIG_LENGTH_HMAC_MD5 = 16,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA1     = 20,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA224   = 28,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA256   = 32,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA384   = 48,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA512   = 64
} knot_tsig_algorithm_digest_length_t;

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
	KNOT_DNSSEC_ALG_RSAMD5             =  1,
	KNOT_DNSSEC_ALG_DH                 =  2,
	KNOT_DNSSEC_ALG_DSA                =  3,

	KNOT_DNSSEC_ALG_RSASHA1            =  5,
	KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1     =  6,
	KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1 =  7,
	KNOT_DNSSEC_ALG_RSASHA256          =  8,

	KNOT_DNSSEC_ALG_RSASHA512          = 10,

	KNOT_DNSSEC_ALG_ECC_GOST           = 12,
	KNOT_DNSSEC_ALG_ECDSAP256SHA256    = 13,
	KNOT_DNSSEC_ALG_ECDSAP384SHA384    = 14
} knot_dnssec_algorithm_t;

/*!
 * \brief NSEC3 hash algorithm numbers.
 */
typedef enum {
	KNOT_NSEC3_ALGORITHM_SHA1 = 1
} knot_nsec3_hash_algorithm_t;

/*!
 * \brief DNS operation code names.
 */
extern knot_lookup_table_t knot_opcode_names[];

/*!
 * \brief DNS reply code names.
 */
extern knot_lookup_table_t knot_rcode_names[];

/*!
 * \brief TSIG key algorithm names.
 */
extern knot_lookup_table_t knot_tsig_alg_names[];

/*!
 * \brief TSIG key algorithm names in a domain form.
 */
extern knot_lookup_table_t knot_tsig_alg_dnames_str[];

/*!
 * \brief TSIG key algorithm domain names.
 */
extern knot_lookup_table_t knot_tsig_alg_dnames[];

/*!
 * \brief DNSSEC algorithm names.
 */
extern knot_lookup_table_t knot_dnssec_alg_names[];

/*!
 * \brief Returns length of TSIG digest for given algorithm.
 *
 * \param algorithm Algorithm code to be used.
 *
 * \retval Digest length for given algorithm.
 */
size_t knot_tsig_digest_length(const uint8_t algorithm);

/*!
 * \brief Returns length of DS digest for given algorithm.
 *
 * \param algorithm Algorithm code to be used.
 *
 * \retval Digest length for given algorithm.
 */
size_t knot_ds_digest_length(const uint8_t algorithm);

/*!
 * \brief Check if algorithm is supported for zone signing.
 *
 * \param algorithm      Algorithm identification.
 * \param nsec3_enabled  NSEC3 enabled for signed zone.
 *
 * \return Given algorithm is allowed for zone signing.
 */
bool knot_dnssec_algorithm_is_zonesign(uint8_t algorithm, bool nsec3_enabled);

#endif /* _KNOT_CONSTS_H_ */

/*! @} */
