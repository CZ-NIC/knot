#ifndef _CUTEDNS_CONSTS_H
#define _CUTEDNS_CONSTS_H

#include <stdint.h>

/*
 * RR types
 * TODO: consider using enum (e.g. to be able to define MAX to the last elem)
 */
const uint16_t DNSLIB_RRTYPE_UNKNOWN = 0;
const uint16_t DNSLIB_RRTYPE_A = 1;		/* a host address */
const uint16_t DNSLIB_RRTYPE_NS = 2;	/* an authoritative name server */
const uint16_t DNSLIB_RRTYPE_MD = 3;	/* a mail destination (Obsolete - use MX) */
const uint16_t DNSLIB_RRTYPE_MF = 4;	/* a mail forwarder (Obsolete - use MX) */
const uint16_t DNSLIB_RRTYPE_CNAME = 5;	/* the canonical name for an alias */
const uint16_t DNSLIB_RRTYPE_SOA = 6;	/* marks the start of a zone of authority */
const uint16_t DNSLIB_RRTYPE_MB = 7;	/* a mailbox domain name (EXPERIMENTAL) */
const uint16_t DNSLIB_RRTYPE_MG = 8;	/* a mail group member (EXPERIMENTAL) */
const uint16_t DNSLIB_RRTYPE_MR = 9;	/* a mail rename domain name (EXPERIMENTAL) */
const uint16_t DNSLIB_RRTYPE_NULL = 10;	/* a null RR (EXPERIMENTAL) */
const uint16_t DNSLIB_RRTYPE_WKS = 11;	/* a well known service description */
const uint16_t DNSLIB_RRTYPE_PTR = 12;	/* a domain name pointer */
const uint16_t DNSLIB_RRTYPE_HINFO = 13;	/* host information */
const uint16_t DNSLIB_RRTYPE_MINFO = 14;	/* mailbox or mail list information */
const uint16_t DNSLIB_RRTYPE_MX = 15;	/* mail exchange */
const uint16_t DNSLIB_RRTYPE_TXT = 16;	/* text strings */
const uint16_t DNSLIB_RRTYPE_RP = 17;	/* RFC1183 */
const uint16_t DNSLIB_RRTYPE_AFSDB = 18;	/* RFC1183 */
const uint16_t DNSLIB_RRTYPE_X25 = 19;	/* RFC1183 */
const uint16_t DNSLIB_RRTYPE_ISDN = 20;	/* RFC1183 */
const uint16_t DNSLIB_RRTYPE_RT = 21;	/* RFC1183 */
const uint16_t DNSLIB_RRTYPE_NSAP = 22;	/* RFC1706 */

const uint16_t DNSLIB_RRTYPE_SIG = 24;	/* 2535typecode */
const uint16_t DNSLIB_RRTYPE_KEY = 25;	/* 2535typecode */
const uint16_t DNSLIB_RRTYPE_PX = 26;	/* RFC2163 */

const uint16_t DNSLIB_RRTYPE_AAAA = 28;	/* ipv6 address */
const uint16_t DNSLIB_RRTYPE_LOC = 29;	/* LOC record  RFC1876 */
const uint16_t DNSLIB_RRTYPE_NXT = 30;	/* 2535typecode */

const uint16_t DNSLIB_RRTYPE_SRV = 33;	/* SRV record RFC2782 */

const uint16_t DNSLIB_RRTYPE_NAPTR = 35;	/* RFC2915 */
const uint16_t DNSLIB_RRTYPE_KX = 36;	/* RFC2230 Key Exchange Delegation Record */
const uint16_t DNSLIB_RRTYPE_CERT = 37;	/* RFC2538 */

const uint16_t DNSLIB_RRTYPE_A6 = 38;	/* RFC2874 */

const uint16_t DNSLIB_RRTYPE_DNAME = 39;	/* RFC2672 */

const uint16_t DNSLIB_RRTYPE_OPT = 41;	/* Pseudo OPT record... */
const uint16_t DNSLIB_RRTYPE_APL = 42;	/* RFC3123 */
const uint16_t DNSLIB_RRTYPE_DS = 43;	/* RFC 4033, 4034, and 4035 */
const uint16_t DNSLIB_RRTYPE_SSHFP = 44;	/* SSH Key Fingerprint */
const uint16_t DNSLIB_RRTYPE_IPSECKEY = 45;	/* public key for ipsec use. RFC 4025 */

const uint16_t DNSLIB_RRTYPE_RRSIG = 46;	/* RFC 4033, 4034, and 4035 */
const uint16_t DNSLIB_RRTYPE_NSEC = 47;	/* RFC 4033, 4034, and 4035 */
const uint16_t DNSLIB_RRTYPE_DNSKEY = 48;	/* RFC 4033, 4034, and 4035 */
const uint16_t DNSLIB_RRTYPE_DHCID = 49;	/* RFC4701 DHCP information */
const uint16_t DNSLIB_RRTYPE_NSEC3 = 50;	/* NSEC3, secure denial, prevents zonewalking */
const uint16_t DNSLIB_RRTYPE_NSEC3PARAM = 51;	/* NSEC3PARAM at zone apex nsec3 parameters */

const uint16_t DNSLIB_RRTYPE_SPF = 99;      /* RFC 4408 */

const uint16_t DNSLIB_RRTYPE_MAX = 99;	// last "real" RR (consider setting to 51)

// not designating any RRs
const uint16_t DNSLIB_RRTYPE_TSIG = 250;
const uint16_t DNSLIB_RRTYPE_IXFR = 251;
const uint16_t DNSLIB_RRTYPE_AXFR = 252;
const uint16_t DNSLIB_RRTYPE_MAILB = 253;	/* A request for mailbox-related records (MB, MG or MR) */
const uint16_t DNSLIB_RRTYPE_MAILA = 254;	/* A request for mail agent RRs (Obsolete - see MX) */
const uint16_t DNSLIB_RRTYPE_ANY = 255;	/* any type (wildcard) */

// totally weird numbers (cannot use for indexing)
const uint16_t DNSLIB_RRTYPE_TA = 32768;	/* DNSSEC Trust Authorities ([Weiler] 2005-12-13) */
const uint16_t DNSLIB_RRTYPE_DLV = 32769;	/* RFC 4431 */

/*
 * OPCODEs
 */
const uint16_t DNSLIB_OPCODE_QUERY = 0; 	/* a standard query (QUERY) */
const uint16_t DNSLIB_OPCODE_IQUERY = 1; 	/* an inverse query (IQUERY) */
const uint16_t DNSLIB_OPCODE_STATUS = 2; 	/* a server status request (STATUS) */
const uint16_t DNSLIB_OPCODE_NOTIFY = 4; 	/* NOTIFY */
const uint16_t DNSLIB_OPCODE_UPDATE = 5; 	/* Dynamic update */

const uint16_t DNSLIB_OPCODE_OFFSET = 14;

/*
 * RCODEs
 */
const uint16_t DNSLIB_RCODE_OK = 0; 	/* No error condition */
const uint16_t DNSLIB_RCODE_FORMAT = 1; 	/* Format error */
const uint16_t DNSLIB_RCODE_SERVFAIL = 2; 	/* Server failure */
const uint16_t DNSLIB_RCODE_NXDOMAIN = 3; 	/* Name Error */
const uint16_t DNSLIB_RCODE_NOTIMPL = 4; 	/* Not implemented */
const uint16_t DNSLIB_RCODE_REFUSED = 5; 	/* Refused */
const uint16_t DNSLIB_RCODE_YXDOMAIN = 6;	/* name should not exist */
const uint16_t DNSLIB_RCODE_YXRRSET = 7;	/* rrset should not exist */
const uint16_t DNSLIB_RCODE_NXRRSET = 8;	/* rrset does not exist */
const uint16_t DNSLIB_RCODE_NOTAUTH = 9;	/* server not authoritative */
const uint16_t DNSLIB_RCODE_NOTZONE = 10;	/* name not inside zone */

/*
 * CLASSes
 */
const uint16_t DNSLIB_CLASS_IN = 1;	/* Class IN */
const uint16_t DNSLIB_CLASS_CS = 2;	/* Class CS */
const uint16_t DNSLIB_CLASS_CH = 3;	/* Class CHAOS */
const uint16_t DNSLIB_CLASS_HS = 4;	/* Class HS */
const uint16_t DNSLIB_CLASS_NONE = 254;	/* Class NONE rfc2136 */
const uint16_t DNSLIB_CLASS_ANY = 255;	/* Class ANY */

/*
 * Other
 */
const unsigned int DNSLIB_MAX_DNAME_LENGTH = 255;
const unsigned int DNSLIB_MAX_DNAME_LABELS = 127;	// 1-char labels

#endif /* _CUTEDNS_CONSTS_H */
