/*
 * File:     descriptor.h
 * Date:     12.11.2010 11:13
 * Author:   jan
 * Project:  
 * Description:   
 */


#ifndef __DESCRIPTOR_H__
#define __DESCRIPTOR_H__

#include <stdint.h>

#include "common.h"

//static const uint MAXRDATALEN=64;
#define MAXRDATALEN 64
/* 64 is in NSD. Seems a little too much, but I'd say it's not a real issue. */

enum dnslib_rr_type 
{
    DNSLIB_RRTYPE_UNKNOWN, /* 0 - an unknown type */
    DNSLIB_RRTYPE_A, /* 1 - a host address */
    DNSLIB_RRTYPE_NS, /* 2 - an authoritative name server */
    DNSLIB_RRTYPE_MD, /* 3 - a mail destination (Obsolete - use MX) */
    DNSLIB_RRTYPE_MF, /* 4 - a mail forwarder (Obsolete - use MX) */
    DNSLIB_RRTYPE_CNAME, /* 5 - the canonical name for an alias */
    DNSLIB_RRTYPE_SOA, /* 6 - marks the start of a zone of authority */
    DNSLIB_RRTYPE_MB, /* 7 - a mailbox domain name (EXPERIMENTAL) */
    DNSLIB_RRTYPE_MG, /* 8 - a mail group member (EXPERIMENTAL) */
    DNSLIB_RRTYPE_MR, /* 9 - a mail rename domain name (EXPERIMENTAL) */
    DNSLIB_RRTYPE_NULL, /* 10 - a null RR (EXPERIMENTAL) */
    DNSLIB_RRTYPE_WKS, /* 11 - a well known service description */
    DNSLIB_RRTYPE_PTR, /* 12 - a domain name pointer */
    DNSLIB_RRTYPE_HINFO, /* 13 - host information */
    DNSLIB_RRTYPE_MINFO, /* 14 - mailbox or mail list information */
    DNSLIB_RRTYPE_MX, /* 15 - mail exchange */
    DNSLIB_RRTYPE_TXT, /* 16 - text strings */
    DNSLIB_RRTYPE_RP, /* 17 - RFC1183 */
    DNSLIB_RRTYPE_AFSDB, /* 18 - RFC1183 */
    DNSLIB_RRTYPE_X25, /* 19 - RFC1183 */
    DNSLIB_RRTYPE_ISDN, /* 20 - RFC1183 */
    DNSLIB_RRTYPE_RT, /* 21 - RFC1183 */
    DNSLIB_RRTYPE_NSAP, /* 22 - RFC1706 */
    
    DNSLIB_RRTYPE_SIG, /* 24 - 2535typecode */
    DNSLIB_RRTYPE_KEY, /* 25 - 2535typecode */
    DNSLIB_RRTYPE_PX, /* 26 - RFC2163 */
    
    DNSLIB_RRTYPE_AAAA, /* 28 - ipv6 address */
    DNSLIB_RRTYPE_LOC, /* 29 - LOC record  RFC1876 */
    DNSLIB_RRTYPE_NXT, /* 30 - 2535typecode */
    
    DNSLIB_RRTYPE_SRV, /* 33 - SRV record RFC2782 */
    
    DNSLIB_RRTYPE_NAPTR, /* 35 - RFC2915 */
    DNSLIB_RRTYPE_KX, /* 36 - RFC2230 Key Exchange Delegation Record */
    DNSLIB_RRTYPE_CERT, /* 37 - RFC2538 */
    
    DNSLIB_RRTYPE_A6, /* 38 - RFC2874 */
    
    DNSLIB_RRTYPE_DNAME, /* 39 - RFC2672 */
    
    DNSLIB_RRTYPE_OPT, /* 41 - Pseudo OPT record... */
    DNSLIB_RRTYPE_APL, /* 42 - RFC3123 */
    DNSLIB_RRTYPE_DS, /* 43 - RFC 4033, 4034, and 4035 */
    DNSLIB_RRTYPE_SSHFP, /* 44 - SSH Key Fingerprint */
    DNSLIB_RRTYPE_IPSECKEY, /* 45 - public key for ipsec use. RFC 4025 */
    
    DNSLIB_RRTYPE_RRSIG, /* 46 - RFC 4033, 4034, and 4035 */
    DNSLIB_RRTYPE_NSEC, /* 47 - RFC 4033, 4034, and 4035 */
    DNSLIB_RRTYPE_DNSKEY, /* 48 - RFC 4033, 4034, and 4035 */
    DNSLIB_RRTYPE_DHCID, /* 49 - RFC4701 DHCP information */
    DNSLIB_RRTYPE_NSEC3, /* 50 - NSEC3, secure denial, prevents zonewalking */
    DNSLIB_RRTYPE_NSEC3PARAM, /* 51 - NSEC3PARAM at zone apex nsec3 parameters */

    /* TODO consider some better way of doing this, indices too high */

    DNSLIB_RRTYPE_SPF = 99,      /* RFC 4408 */

    // not designating any RRs
    DNSLIB_RRTYPE_TSIG = 250,
    DNSLIB_RRTYPE_IXFR = 251,
    DNSLIB_RRTYPE_AXFR = 252,
    DNSLIB_RRTYPE_MAILB = 253,	/* A request for mailbox-related records (MB, MG or MR) */
    DNSLIB_RRTYPE_MAILA = 254,	/* A request for mail agent RRs (Obsolete - see MX) */
    DNSLIB_RRTYPE_ANY = 255,	/* any type (wildcard) */

    // totally weird numbers (cannot use for indexing)
    DNSLIB_RRTYPE_TA = 32768,	/* DNSSEC Trust Authorities ([Weiler] 2005-12-13) */
    DNSLIB_RRTYPE_DLV = 32769/* RFC 4431 */
};

typedef enum dnslib_rr_type dnslib_rr_type_t;

enum dnslib_rdata_wireformat
{
  	DNSLIB_RDATA_WF_COMPRESSED_DNAME,   /* Possibly compressed domain name.  */
	  DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME, /* Uncompressed domain name.  */
	  DNSLIB_RDATA_WF_LITERAL_DNAME,      /* Literal (not downcased) dname.  */
	  DNSLIB_RDATA_WF_BYTE,		           /* 8-bit integer.  */
	  DNSLIB_RDATA_WF_SHORT,     		     /* 16-bit integer.  */
	  DNSLIB_RDATA_WF_LONG,		           /* 32-bit integer.  */
	  DNSLIB_RDATA_WF_TEXT,		           /* Text string.  */
	  DNSLIB_RDATA_WF_A,		               /* 32-bit IPv4 address.  */
	  DNSLIB_RDATA_WF_AAAA,		           /* 128-bit IPv6 address.  */
	  DNSLIB_RDATA_WF_BINARY, 	           /* Binary data (unknown length).  */
	  DNSLIB_RDATA_WF_BINARYWITHLENGTH,   /* Binary data preceded by 1 byte length */
	  DNSLIB_RDATA_WF_APL,		             /* APL data.  */
	  DNSLIB_RDATA_WF_IPSECGATEWAY	       /* IPSECKEY gateway ip4, ip6 or dname. */
};

typedef enum dnslib_rdatawireformat dnslib_rdata_wireformat_t;

struct dnslib_rrtype_descriptor
{
  	uint16_t    type;	/* RR type */
  	const char *name;	/* Textual name.  */
  	uint32_t    length;	/* Maximum number of RDATAs.  */
  	uint8_t     wireformat[MAXRDATALEN]; /* rdata_wireformat_type */
};

typedef struct dnslib_rrtype_descriptor dnslib_rrtype_descriptor_t;

#endif

/* end of file descriptor.h */
