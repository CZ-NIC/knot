/*!
 * \file descriptor.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>, most of the work by the NSD team
 *
 * \brief Contains resource record descriptor and its API
 *
 * \note Most of the constants and functions were taken from NSD's dns.h.
 *
 * \todo Link to NDS's license + add license !!!
 * 
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_DESCRIPTOR_H_
#define _KNOT_DNSLIB_DESCRIPTOR_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

enum mxrdtln {
	/*! \brief Maximum items in RDATA wireformat. */
	DNSLIB_MAX_RDATA_ITEMS = 64,
	/*! \brief Maximum size of one item in RDATA wireformat. */
	DNSLIB_MAX_RDATA_ITEM_SIZE = 65534,
	/*! \brief Maximum wire size of one RDATA. */
	DNSLIB_MAX_RDATA_WIRE_SIZE =
	DNSLIB_MAX_RDATA_ITEMS * DNSLIB_MAX_RDATA_ITEM_SIZE
};
//#define MAXRDATALEN 64

/* 64 is in NSD. Seems a little too much, but I'd say it's not a real issue. */

/*!
 * \brief Resource record class codes.
 */
enum dnslib_rr_class {
	DNSLIB_CLASS_IN = 1,
	DNSLIB_CLASS_CS,
	DNSLIB_CLASS_CH,
	DNSLIB_CLASS_HS,
	DNSLIB_CLASS_NONE = 254,
	DNSLIB_CLASS_ANY = 255
};

typedef enum dnslib_rr_class dnslib_rr_class_t;

/*!
 * \brief Resource record type constants.
 */
enum dnslib_rr_type {
	DNSLIB_RRTYPE_UNKNOWN, /*!< 0 - an unknown type */
	DNSLIB_RRTYPE_A, /*!< 1 - a host address */
	DNSLIB_RRTYPE_NS, /*!< 2 - an authoritative name server */
	DNSLIB_RRTYPE_MD, /*!< 3 - a mail destination (Obsolete - use MX) */
	DNSLIB_RRTYPE_MF, /*!< 4 - a mail forwarder (Obsolete - use MX) */
	DNSLIB_RRTYPE_CNAME, /*!< 5 - the canonical name for an alias */
	DNSLIB_RRTYPE_SOA, /*!< 6 - marks the start of a zone of authority */
	DNSLIB_RRTYPE_MB, /*!< 7 - a mailbox domain name (EXPERIMENTAL) */
	DNSLIB_RRTYPE_MG, /*!< 8 - a mail group member (EXPERIMENTAL) */
	DNSLIB_RRTYPE_MR, /*!< 9 - a mail rename domain name (EXPERIMENTAL) */
	DNSLIB_RRTYPE_NULL, /*!< 10 - a null RR (EXPERIMENTAL) */
	DNSLIB_RRTYPE_WKS, /*!< 11 - a well known service description */
	DNSLIB_RRTYPE_PTR, /*!< 12 - a domain name pointer */
	DNSLIB_RRTYPE_HINFO, /*!< 13 - host information */
	DNSLIB_RRTYPE_MINFO, /*!< 14 - mailbox or mail list information */
	DNSLIB_RRTYPE_MX, /*!< 15 - mail exchange */
	DNSLIB_RRTYPE_TXT, /*!< 16 - text strings */
	DNSLIB_RRTYPE_RP, /*!< 17 - RFC1183 */
	DNSLIB_RRTYPE_AFSDB, /*!< 18 - RFC1183 */
	DNSLIB_RRTYPE_X25, /*!< 19 - RFC1183 */
	DNSLIB_RRTYPE_ISDN, /*!< 20 - RFC1183 */
	DNSLIB_RRTYPE_RT, /*!< 21 - RFC1183 */
	DNSLIB_RRTYPE_NSAP, /*!< 22 - RFC1706 */

	DNSLIB_RRTYPE_SIG = 24, /*!< 24 - 2535typecode */
	DNSLIB_RRTYPE_KEY, /*!< 25 - 2535typecode */
	DNSLIB_RRTYPE_PX, /*!< 26 - RFC2163 */

	DNSLIB_RRTYPE_AAAA = 28, /*!< 28 - ipv6 address */
	DNSLIB_RRTYPE_LOC, /*!< 29 - LOC record  RFC1876 */
	DNSLIB_RRTYPE_NXT, /*!< 30 - 2535typecode */

	DNSLIB_RRTYPE_SRV = 33, /*!< 33 - SRV record RFC2782 */

	DNSLIB_RRTYPE_NAPTR = 35, /*!< 35 - RFC2915 */
	DNSLIB_RRTYPE_KX, /*!< 36 - RFC2230 Key Exchange Delegation Record */
	DNSLIB_RRTYPE_CERT, /*!< 37 - RFC2538 */
	DNSLIB_RRTYPE_A6, /*!< 38 - RFC2874 */
	DNSLIB_RRTYPE_DNAME, /*!< 39 - RFC2672 */

	DNSLIB_RRTYPE_OPT = 41, /*!< 41 - Pseudo OPT record... */
	DNSLIB_RRTYPE_APL, /*!< 42 - RFC3123 */
	DNSLIB_RRTYPE_DS, /*!< 43 - RFC 4033, 4034, and 4035 */
	DNSLIB_RRTYPE_SSHFP, /*!< 44 - SSH Key Fingerprint */
	DNSLIB_RRTYPE_IPSECKEY, /*!< 45 - public key for ipsec use. RFC 4025 */
	DNSLIB_RRTYPE_RRSIG, /*!< 46 - RFC 4033, 4034, and 4035 */
	DNSLIB_RRTYPE_NSEC, /*!< 47 - RFC 4033, 4034, and 4035 */
	DNSLIB_RRTYPE_DNSKEY, /*!< 48 - RFC 4033, 4034, and 4035 */
	DNSLIB_RRTYPE_DHCID, /*!< 49 - RFC4701 DHCP information */
	/*!
	 * \brief 50 - NSEC3, secure denial, prevents zonewalking
	 */
	DNSLIB_RRTYPE_NSEC3,
	/*!
	 * \brief  51 - NSEC3PARAM at zone apex nsec3 parameters
	 */
	DNSLIB_RRTYPE_NSEC3PARAM, 

	/* TODO consider some better way of doing this, indices too high */

	DNSLIB_RRTYPE_SPF = 99,      /*!< RFC 4408 */

	// not designating any RRs
	DNSLIB_RRTYPE_TSIG = 250, /*!< TSIG (not an actual RR). */
	DNSLIB_RRTYPE_IXFR = 251, /*!< IXFR (not an actual RR). */
	DNSLIB_RRTYPE_AXFR = 252, /*!< AXFR (not an actual RR). */
	/*!
	 * \brief A request for mailbox-related records (MB, MG or MR)
	 */
	DNSLIB_RRTYPE_MAILB = 253,
	/*!
	 * \brief A request for mail agent RRs (Obsolete - see MX)
	 */
	DNSLIB_RRTYPE_MAILA = 254,
	DNSLIB_RRTYPE_ANY = 255, /*!< any type (wildcard) */

	// totally weird numbers (cannot use for indexing)
	DNSLIB_RRTYPE_TA = 32768, /*!< DNSSEC Trust Authorities */
	DNSLIB_RRTYPE_DLV = 32769 /*!< RFC 4431 */
};

/*!
 * \brief Enum containing RR type codes.
 *
 * \todo Not all indices can be used for indexing.
 */
typedef enum dnslib_rr_type dnslib_rr_type_t;

/*! \brief Last normal RR type. */
static const uint DNSLIB_RRTYPE_LAST = DNSLIB_RRTYPE_NSEC3PARAM;

/*! \brief Constants characterising the wire format of RDATA items. */
enum dnslib_rdata_wireformat {
	/*!
	 * \brief Possibly compressed domain name.
	 */	
	DNSLIB_RDATA_WF_COMPRESSED_DNAME = 50,
	DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME = 51, /*!< Uncompressed domain name.  */
	DNSLIB_RDATA_WF_LITERAL_DNAME = 52, /*!< Literal (not downcased) dname.  */
	DNSLIB_RDATA_WF_BYTE = 1, /*!< 8-bit integer.  */
	DNSLIB_RDATA_WF_SHORT = 2, /*!< 16-bit integer.  */
	DNSLIB_RDATA_WF_LONG = 4, /*!< 32-bit integer.  */
	DNSLIB_RDATA_WF_TEXT = 53, /*!< Text string.  */
	DNSLIB_RDATA_WF_A = 58, /*!< 32-bit IPv4 address.  */
	DNSLIB_RDATA_WF_AAAA = 16, /*!< 128-bit IPv6 address.  */
	DNSLIB_RDATA_WF_BINARY = 54, /*!< Binary data (unknown length).  */
	/*!
	 * \brief Binary data preceded by 1 byte length 
	 */
	DNSLIB_RDATA_WF_BINARYWITHLENGTH = 55,
	DNSLIB_RDATA_WF_APL = 56, /*!< APL data.  */
	DNSLIB_RDATA_WF_IPSECGATEWAY = 57 /*!< IPSECKEY gateway ip4, ip6 or dname. */
};

/*! \brief Constants characterising the format of RDATA items in zone file. */
enum dnslib_rdata_zoneformat
{
	DNSLIB_RDATA_ZF_DNAME,		/* Domain name.  */
	DNSLIB_RDATA_ZF_LITERAL_DNAME,	/* DNS name (not lowercased domain name).  */
	DNSLIB_RDATA_ZF_TEXT,		/* Text string.  */
	DNSLIB_RDATA_ZF_BYTE,		/* 8-bit integer.  */
	DNSLIB_RDATA_ZF_SHORT,		/* 16-bit integer.  */
	DNSLIB_RDATA_ZF_LONG,		/* 32-bit integer.  */
	DNSLIB_RDATA_ZF_A,		/* 32-bit IPv4 address.  */
	DNSLIB_RDATA_ZF_AAAA,		/* 128-bit IPv6 address.  */
	DNSLIB_RDATA_ZF_RRTYPE,		/* RR type.  */
	DNSLIB_RDATA_ZF_ALGORITHM,	/* Cryptographic algorithm.  */
	DNSLIB_RDATA_ZF_CERTIFICATE_TYPE,
	DNSLIB_RDATA_ZF_PERIOD,		/* Time period.  */
	DNSLIB_RDATA_ZF_TIME,
	DNSLIB_RDATA_ZF_BASE64,		/* Base-64 binary data.  */
	DNSLIB_RDATA_ZF_BASE32,		/* Base-32 binary data.  */
	DNSLIB_RDATA_ZF_HEX,		/* Hexadecimal binary data.  */
	DNSLIB_RDATA_ZF_HEX_LEN,	/* Hexadecimal binary data. Skip initial length byte. */
	DNSLIB_RDATA_ZF_NSAP,		/* NSAP.  */
	DNSLIB_RDATA_ZF_APL,		/* APL.  */
	DNSLIB_RDATA_ZF_IPSECGATEWAY,	/* IPSECKEY gateway ip4, ip6 or dname. */
	DNSLIB_RDATA_ZF_SERVICES,	/* Protocol and port number bitmap.  */
	DNSLIB_RDATA_ZF_NXT,		/* NXT type bitmap.  */
	DNSLIB_RDATA_ZF_NSEC,		/* NSEC type bitmap.  */
	DNSLIB_RDATA_ZF_LOC,		/* Location data.  */
	DNSLIB_RDATA_ZF_UNKNOWN	/* Unknown data.  */
};

/*! \brief Constants characterising the wire format of RDATA items. */
typedef enum dnslib_rdata_zoneformat dnslib_rdata_zoneformat_t;

/*! \brief Enum containing wireformat codes. */
typedef enum dnslib_rdatawireformat dnslib_rdata_wireformat_t;

/*! \brief Structure holding RR descriptor. */
struct dnslib_rrtype_descriptor {
	uint16_t type;          /*!< RR type */
	const char *name;       /*!< Textual name.  */
	uint8_t length;         /*!< Maximum number of RDATA items.  */

	/*! \brief Wire format specification for the RDATA. */
	uint8_t wireformat[DNSLIB_MAX_RDATA_ITEMS];

	/*! \brief Zone file format specification for the RDATA. */
	uint8_t zoneformat[DNSLIB_MAX_RDATA_ITEMS];

	bool fixed_items; /*!< Has fixed number of RDATA items? */
};

/*! \brief Structure holding RR descriptor. */
typedef struct dnslib_rrtype_descriptor dnslib_rrtype_descriptor_t;

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
dnslib_rrtype_descriptor_t *dnslib_rrtype_descriptor_by_type(uint16_t type);

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
dnslib_rrtype_descriptor_t *dnslib_rrtype_descriptor_by_name(const char *name);

/*!
 * \brief Converts numeric type representation to mnemonic string.
 *
 * \param rrtype Type RR type code to be converted.
 *
 * \return Mnemonic string if found, str(TYPE[rrtype]) otherwise.
 */
const char *dnslib_rrtype_to_string(uint16_t rrtype);

/*!
 * \brief Converts mnemonic string representation of a type to numeric one.
 *
 * \param name Mnemonic string to be converted.
 *
 * \return Correct code if found, 0 otherwise.
 */
uint16_t dnslib_rrtype_from_string(const char *name);

/*!
 * \brief Converts numeric class representation to string one.
 *
 * \param rrclass Class code to be converted.
 *
 * \return String represenation of class if found,
 *         str(CLASS[rrclass]) otherwise.
 */
const char *dnslib_rrclass_to_string(uint16_t rrclass);

/*!
 * \brief Converts string representation of a class to numeric one.
 *
 * \param name Class string to be converted.
 *
 * \return Correct code if found, 0 otherwise.
 */
uint16_t dnslib_rrclass_from_string(const char *name);

/*!
 * \brief Returns size of wireformat type in bytes.
 *
 * \param wire_type Wireformat type.
 *
 * \retval Size of given type on success.
 * \retval 0 on unknown type or type that has no length.
 */
size_t dnslib_wireformat_size(uint wire_type);

#endif /* _KNOT_DNSLIB_DESCRIPTOR_H_ */

/*! @} */

