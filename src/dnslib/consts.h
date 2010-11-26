#ifndef _CUTEDNS_DNSLIB_CONSTS_H_
#define _CUTEDNS_DNSLIB_CONSTS_H_

#include <stdint.h>

/*
 * OPCODEs
 */
const uint16_t DNSLIB_OPCODE_QUERY = 0;  /* a standard query (QUERY) */
const uint16_t DNSLIB_OPCODE_IQUERY = 1; /* an inverse query (IQUERY) */
const uint16_t DNSLIB_OPCODE_STATUS = 2; /* a server status request (STATUS) */
const uint16_t DNSLIB_OPCODE_NOTIFY = 4; /* NOTIFY */
const uint16_t DNSLIB_OPCODE_UPDATE = 5; /* Dynamic update */

const uint16_t DNSLIB_OPCODE_OFFSET = 14;

/*
 * RCODEs
 */
const uint16_t DNSLIB_RCODE_OK = 0; 		/* No error condition */
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

#endif /* _CUTEDNS_DNSLIB_CONSTS_H_ */
