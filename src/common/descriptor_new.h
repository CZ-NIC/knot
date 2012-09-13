/*!
 * \file descriptor_new.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>,
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
	KNOT_CLASS_IN = 1,
	KNOT_CLASS_NONE = 254,
	KNOT_CLASS_ANY = 255
};

/*!
 * \brief Resource record type constants.
 */
enum knot_rr_type {
	KNOT_RRTYPE_A, /*!< 1 - a host address */
	KNOT_RRTYPE_NS, /*!< 2 - an authoritative name server */
	KNOT_RRTYPE_CNAME = 5, /*!< 5 - the canonical name for an alias */
	KNOT_RRTYPE_SOA, /*!< 6 - marks the start of a zone of authority */
	KNOT_RRTYPE_PTR = 12, /*!< 12 - a domain name pointer */
	KNOT_RRTYPE_HINFO, /*!< 13 - host information */
	KNOT_RRTYPE_MINFO, /*!< 14 - mailbox or mail list information */
	KNOT_RRTYPE_MX, /*!< 15 - mail exchange */
	KNOT_RRTYPE_TXT, /*!< 16 - text strings */
	KNOT_RRTYPE_RP, /*!< 17 - Responsible person. */
	KNOT_RRTYPE_AFSDB, /*!< 18 - RFC1183 */
	KNOT_RRTYPE_NSAP = 22, /*!< 22 - RFC1706 */

	KNOT_RRTYPE_AAAA = 28, /*!< 28 - ipv6 address */
	KNOT_RRTYPE_LOC, /*!< 29 - LOC record  RFC1876 */

	KNOT_RRTYPE_SRV = 33, /*!< 33 - SRV record RFC2782 */

	KNOT_RRTYPE_NAPTR = 35, /*!< 35 - RFC2915 */
	KNOT_RRTYPE_KX, /*!< 36 - RFC2230 Key Exchange Delegation Record */
	KNOT_RRTYPE_CERT, /*!< 37 - RFC2538 */
	KNOT_RRTYPE_DNAME = 39, /*!< 39 - RFC2672 */

	KNOT_RRTYPE_OPT = 41, /*!< 41 - Pseudo OPT record... */
	KNOT_RRTYPE_APL, /*!< 42 - RFC3123 */
	KNOT_RRTYPE_DS, /*!< 43 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_SSHFP, /*!< 44 - SSH Key Fingerprint */
	KNOT_RRTYPE_IPSECKEY, /*!< 45 - public key for ipsec use. RFC 4025 */
	KNOT_RRTYPE_RRSIG, /*!< 46 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_NSEC, /*!< 47 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_DNSKEY, /*!< 48 - RFC 4033, 4034, and 4035 */
	KNOT_RRTYPE_DHCID, /*!< 49 - RFC4701 DHCP information */
	KNOT_RRTYPE_NSEC3, /*!< 50 - NSEC3, secure denial */
	KNOT_RRTYPE_NSEC3PARAM, /*!< 51 - nsec3 parameters */
	KNOT_RRTYPE_TLSA = 52, /*!< DANE */

	KNOT_RRTYPE_SPF = 99,      /*!< RFC 4408 */

	KNOT_RRTYPE_TSIG = 250, /*!< TSIG - RFC2845. */
	
	KNOT_RRTYPE_IXFR = 251, /*!< IXFR (not an actual RR). */
	KNOT_RRTYPE_AXFR = 252, /*!< AXFR (not an actual RR). */
	KNOT_RRTYPE_ANY = 255, /*!< any type (wildcard) */
};

/*! \brief Constants characterising the wire format of RDATA items. */
enum knot_rdata_wireformat {
	/*!
	 * \brief Possibly compressed domain name.
	 */	
	KNOT_RDATA_WF_COMPRESSED_DNAME = -100,
	KNOT_RDATA_WF_UNCOMPRESSED_DNAME, /*!< Uncompressed domain name.  */
	KNOT_RDATA_WF_LITERAL_DNAME, /*!< Literal (not downcased) dname.  */
	KNOT_RDATA_WF_NAPTR_HEADER,
	KNOT_RDATA_WF_REMAINDER,
};

struct knot_descriptor {
	uint16_t type;
	int wire[16];
};

typedef struct knot_descriptor knot_descriptor_t;

#endif // _KNOT_DESCRIPTOR_NEW_H_
