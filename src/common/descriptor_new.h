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
/*!
 * \file descriptor_new.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * @{
 */

#ifndef _KNOT_DESCRIPTOR_NEW_H_
#define _KNOT_DESCRIPTOR_NEW_H_

#include <stdint.h>

/*!
 * \brief Resource record class codes.
 */
enum knot_rr_class {
	KNOT_CLASS_IN   =   1,
	KNOT_CLASS_NONE = 254,
	KNOT_CLASS_ANY  = 255,
};

/*!
 * \brief Resource record type constants.
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

	KNOT_RRTYPE_KEY        =  25, /*!< For security key. */

	KNOT_RRTYPE_AAAA       =  28, /*!< IPv6 address. */
	KNOT_RRTYPE_LOC        =  29, /*!< Location information. */

	KNOT_RRTYPE_SRV        =  33, /*!< Server selection. */

	KNOT_RRTYPE_NAPTR      =  35, /*!< Naming authority pointer . */
	KNOT_RRTYPE_KX         =  36, /*!< Key exchanger. */
	KNOT_RRTYPE_CERT       =  37, /*!< Certificate record. */

	KNOT_RRTYPE_DNAME      =  39, /*!< Delegation name. */

	KNOT_RRTYPE_OPT        =  41, /*!< Option for EDNS*/
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
	KNOT_RRTYPE_TLSA       =  52, /*!< DANE. */

	KNOT_RRTYPE_SPF        =  99, /*!< Sender policy framework. */

	KNOT_RRTYPE_TKEY       = 249, /*!< Secret key for TSIG. */
	KNOT_RRTYPE_TSIG       = 250, /*!< Transaction signature. */
	KNOT_RRTYPE_IXFR       = 251, /*!< Incremental zone transfer. */
	KNOT_RRTYPE_AXFR       = 252, /*!< Authoritative zone transfer. */

	KNOT_RRTYPE_ANY        = 255, /*!< Any record. */
};

/*!
 * \brief Constants characterising the wire format of RDATA items.
 */
enum knot_rdata_wireformat {
	/*!< Possibly compressed dname. */
	KNOT_RDATA_WF_COMPRESSED_DNAME   = -12,
	/*!< Uncompressed dname. */
	KNOT_RDATA_WF_UNCOMPRESSED_DNAME = -11,
	/*!< Dname with preserved letter cases. */
	KNOT_RDATA_WF_LITERAL_DNAME      = -10,
	/*!< Initial part of NAPTR record before dname. */
	KNOT_RDATA_WF_NAPTR_HEADER,
	/*!< Uninteresting final part of a record. */
	KNOT_RDATA_WF_REMAINDER,
	/*!< The last descriptor in array. */
	KNOT_RDATA_WF_END                =   0,
};

/*!
 * \brief Array which describes record structure.
 */
typedef int knot_descriptor_t[8];

/*!
 * \brief Gets RR descriptor for given RR name.
 *
 * \param name Mnemonic of RR type whose descriptor should be returned.
 *
 * \return RR descriptor for given name, NULL descriptor if
 *         unknown type.
 */
const knot_descriptor_t *knot_descriptor_by_type(const uint16_t type);

#endif // _KNOT_DESCRIPTOR_NEW_H_

/*! @} */
