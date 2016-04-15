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
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KNOT_MAX_RDATA_BLOCKS	8
#define KNOT_MAX_RDATA_DNAMES	2	// Update this when defining new RR types!

/*!
 * \brief Resource record class codes.
 *
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
 */
enum knot_rr_class {
	KNOT_CLASS_IN   =   1,
	KNOT_CLASS_CH   =   3,
	KNOT_CLASS_NONE = 254,
	KNOT_CLASS_ANY  = 255
};

/*!
 * \brief Resource record type constants.
 *
 * References:
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
 * RFC 3597#4
 *
 * METATYPE: Contains DNS data that can't be in a zone file.
 * QTYPE: Specifies DNS query type; can't be in a zone file.
 */
enum knot_rr_type {
	KNOT_RRTYPE_A          =   1, /*!< An IPv4 host address. */
	KNOT_RRTYPE_NS         =   2, /*!< An authoritative name server. */

	KNOT_RRTYPE_CNAME      =   5, /*!< The canonical name for an alias. */
	KNOT_RRTYPE_SOA        =   6, /*!< The start of a zone of authority. */

	KNOT_RRTYPE_PTR        =  12, /*!< A domain name pointer. */
	KNOT_RRTYPE_HINFO      =  13, /*!< A host information. */
	KNOT_RRTYPE_MINFO      =  14, /*!< A mailbox information. */
	KNOT_RRTYPE_MX         =  15, /*!< Mail exchange. */
	KNOT_RRTYPE_TXT        =  16, /*!< Text strings. */
	KNOT_RRTYPE_RP         =  17, /*!< For responsible person. */
	KNOT_RRTYPE_AFSDB      =  18, /*!< For AFS Data Base location. */

	KNOT_RRTYPE_RT         =  21, /*!< For route through. */

	KNOT_RRTYPE_SIG        =  24, /*!< METATYPE. Transaction signature. */
	KNOT_RRTYPE_KEY        =  25, /*!< For security key. */

	KNOT_RRTYPE_AAAA       =  28, /*!< IPv6 address. */
	KNOT_RRTYPE_LOC        =  29, /*!< Location information. */

	KNOT_RRTYPE_SRV        =  33, /*!< Server selection. */

	KNOT_RRTYPE_NAPTR      =  35, /*!< Naming authority pointer . */
	KNOT_RRTYPE_KX         =  36, /*!< Key exchanger. */
	KNOT_RRTYPE_CERT       =  37, /*!< Certificate record. */

	KNOT_RRTYPE_DNAME      =  39, /*!< Delegation name. */

	KNOT_RRTYPE_OPT        =  41, /*!< METATYPE. Option for EDNS. */
	KNOT_RRTYPE_APL        =  42, /*!< Address prefix list. */
	KNOT_RRTYPE_DS         =  43, /*!< Delegation signer. */
	KNOT_RRTYPE_SSHFP      =  44, /*!< SSH public key fingerprint. */
	KNOT_RRTYPE_IPSECKEY   =  45, /*!< IPSEC key. */
	KNOT_RRTYPE_RRSIG      =  46, /*!< DNSSEC signature. */
	KNOT_RRTYPE_NSEC       =  47, /*!< Next-secure record. */
	KNOT_RRTYPE_DNSKEY     =  48, /*!< DNS key. */
	KNOT_RRTYPE_DHCID      =  49, /*!< DHCP identifier. */
	KNOT_RRTYPE_NSEC3      =  50, /*!< NSEC version 3. */
	KNOT_RRTYPE_NSEC3PARAM =  51, /*!< NSEC3 parameters. */
	KNOT_RRTYPE_TLSA       =  52, /*!< DANE record. */

	KNOT_RRTYPE_CDS        =  59, /*!< Child delegation signer. */
	KNOT_RRTYPE_CDNSKEY    =  60, /*!< Child DNS key. */

	KNOT_RRTYPE_SPF        =  99, /*!< Sender policy framework. */

	KNOT_RRTYPE_NID        = 104, /*!< Node identifier. */
	KNOT_RRTYPE_L32        = 105, /*!< 32-bit network locator. */
	KNOT_RRTYPE_L64        = 106, /*!< 64-bit network locator. */
	KNOT_RRTYPE_LP         = 107, /*!< Subnetwork name. */
	KNOT_RRTYPE_EUI48      = 108, /*!< 48-bit extended unique identifier. */
	KNOT_RRTYPE_EUI64      = 109, /*!< 64-bit extended unique identifier. */

	KNOT_RRTYPE_TKEY       = 249, /*!< METATYPE. Transaction key. */
	KNOT_RRTYPE_TSIG       = 250, /*!< METATYPE. Transaction signature. */
	KNOT_RRTYPE_IXFR       = 251, /*!< QTYPE. Incremental zone transfer. */
	KNOT_RRTYPE_AXFR       = 252, /*!< QTYPE. Authoritative zone transfer. */

	KNOT_RRTYPE_ANY        = 255, /*!< QTYPE. Any record. */
	KNOT_RRTYPE_URI        = 256, /*!< Uniform resource identifier. */
	KNOT_RRTYPE_CAA        = 257, /*!< Certification authority restriction. */
};

/*!
 * \brief Some (OBSOLETE) resource record type constants.
 *
 * References:
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
 * RFC 3597#4
 *
 * \note These records can contain compressed domain name in rdata so
 *       it is important to know the position of them during transfers.
 */
enum knot_obsolete_rr_type {
	KNOT_RRTYPE_MD         =   3,
	KNOT_RRTYPE_MF         =   4,
	KNOT_RRTYPE_MB         =   7,
	KNOT_RRTYPE_MG         =   8,
	KNOT_RRTYPE_MR         =   9,
	KNOT_RRTYPE_PX         =  26,
	KNOT_RRTYPE_NXT        =  30
};

/*!
 * \brief Constants characterising the wire format of RDATA items.
 */
enum knot_rdata_wireformat {
	/*!< Dname must not be compressed. */
	KNOT_RDATA_WF_FIXED_DNAME          = -10,
	/*!< Dname can be both compressed and decompressed. */
	KNOT_RDATA_WF_COMPRESSIBLE_DNAME,
	/*!< Dname can be decompressed. */
	KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME,
	/*!< Initial part of NAPTR record before dname. */
	KNOT_RDATA_WF_NAPTR_HEADER,
	/*!< Final part of a record. */
	KNOT_RDATA_WF_REMAINDER,
	/*!< The last descriptor in array. */
	KNOT_RDATA_WF_END                  =   0
};

/*!
 * \brief Structure describing rdata.
 */
typedef struct {
	/*!< Item types describing rdata. */
	const int  block_types[KNOT_MAX_RDATA_BLOCKS];
	/*!< RR type name. */
	const char *type_name;
} knot_rdata_descriptor_t;

/*!
 * \brief Gets rdata descriptor for given RR name.
 *
 * \param name Mnemonic of RR type whose descriptor should be returned.
 *
 * \retval RR descriptor for given name, NULL descriptor if
 *         unknown type.
 */
const knot_rdata_descriptor_t *knot_get_rdata_descriptor(const uint16_t type);

/*!
 * \brief Gets rdata descriptor for given RR name (obsolete version).
 *
 * \param name Mnemonic of RR type whose descriptor should be returned.
 *
 * \retval RR descriptor for given name, NULL descriptor if
 *         unknown type.
 */
const knot_rdata_descriptor_t *knot_get_obsolete_rdata_descriptor(const uint16_t type);

/*!
 * \brief Converts numeric type representation to mnemonic string.
 *
 * \param rrtype  Type RR type code to be converted.
 * \param out     Output buffer.
 * \param out_len Length of the output buffer.
 *
 * \retval Length of output string.
 * \retval -1 if error.
 */
int knot_rrtype_to_string(const uint16_t rrtype,
                          char           *out,
                          const size_t   out_len);

/*!
 * \brief Converts mnemonic string representation of a type to numeric one.
 *
 * \param name Mnemonic string to be converted.
 * \param num  Output variable.
 *
 * \retval  0 if OK.
 * \retval -1 if error.
 */
int knot_rrtype_from_string(const char *name, uint16_t *num);

/*!
 * \brief Converts numeric class representation to the string one.
 *
 * \param rrclass Class code to be converted.
 * \param out     Output buffer.
 * \param out_len Length of the output buffer.
 *
 * \retval Length of output string.
 * \retval -1 if error.
 */
int knot_rrclass_to_string(const uint16_t rrclass,
                           char           *out,
                           const size_t   out_len);

/*!
 * \brief Converts string representation of a class to numeric one.
 *
 * \param name Mnemonic string to be converted.
 * \param num  Output variable.
 *
 * \retval  0 if OK.
 * \retval -1 if error.
 */
int knot_rrclass_from_string(const char *name, uint16_t *num);

/*!
 * \brief Checks if given item is one of metatypes or qtypes.
 *
 * \param item Item value.
 *
 * \retval > 0 if YES.
 * \retval 0 if NO.
 */
int knot_rrtype_is_metatype(const uint16_t type);

/*!
 * \brief Checks if given item is one of the DNSSEC types.
 *
 * \param item Item value.
 *
 * \retval > 0 if YES.
 * \retval 0 if NO.
 */
int knot_rrtype_is_dnssec(const uint16_t type);

/*!
 * \brief Checks whether the given type requires additional processing.
 *
 * Only MX, NS and SRV types require additional processing.
 *
 * \param type Type to check.
 *
 * \retval <> 0 if additional processing is needed for \a qtype.
 * \retval 0 otherwise.
 */
int knot_rrtype_additional_needed(const uint16_t type);

/*!
 * \brief Checks whether the RDATA domain names should be lowercased in
 *        canonical format of RRSet of the given type.
 *
 * Types that should be lowercased are accorrding to RFC 4034, Section 6.2,
 * except for NSEC (updated by RFC 6840, Section 5.1) and A6 (not supported).
 *
 * \param type RRSet type to check.
 *
 * \retval true If RDATA dnames for type should be lowercased in canonical format.
 * \retval false Otherwise.
 */
bool knot_rrtype_should_be_lowercased(const uint16_t type);

/*! @} */
