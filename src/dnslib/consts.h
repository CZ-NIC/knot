/*!
 * \file consts.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Contains some DNS-related constants.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_CONSTS_H_
#define _KNOT_DNSLIB_CONSTS_H_

#include <stdint.h>
#include "dnslib/descriptor.h"

/*
 * OPCODEs
 */
static const uint16_t DNSLIB_OPCODE_QUERY = 0;  /* a standard query (QUERY) */
static const uint16_t DNSLIB_OPCODE_IQUERY = 1; /* an inverse query (IQUERY) */
static const uint16_t DNSLIB_OPCODE_STATUS = 2; /* a server status request (STATUS) */
static const uint16_t DNSLIB_OPCODE_NOTIFY = 4; /* NOTIFY */
static const uint16_t DNSLIB_OPCODE_UPDATE = 5; /* Dynamic update */

static const uint16_t DNSLIB_OPCODE_OFFSET = 14;

/*
 * RCODEs
 */
static const uint16_t DNSLIB_RCODE_NOERROR = 0; 	/* No error condition */
static const uint16_t DNSLIB_RCODE_FORMERR = 1; 	/* Format error */
static const uint16_t DNSLIB_RCODE_SERVFAIL = 2; 	/* Server failure */
static const uint16_t DNSLIB_RCODE_NXDOMAIN = 3; 	/* Name Error */
static const uint16_t DNSLIB_RCODE_NOTIMPL = 4; 	/* Not implemented */
static const uint16_t DNSLIB_RCODE_REFUSED = 5; 	/* Refused */
static const uint16_t DNSLIB_RCODE_YXDOMAIN = 6;	/* name should not exist */
static const uint16_t DNSLIB_RCODE_YXRRSET = 7;	/* rrset should not exist */
static const uint16_t DNSLIB_RCODE_NXRRSET = 8;	/* rrset does not exist */
static const uint16_t DNSLIB_RCODE_NOTAUTH = 9;	/* server not authoritative */
static const uint16_t DNSLIB_RCODE_NOTZONE = 10;	/* name not inside zone */

/*
 * CLASSes
 */
//const uint16_t DNSLIB_CLASS_IN = 1;	/* Class IN */
//const uint16_t DNSLIB_CLASS_CS = 2;	/* Class CS */
//const uint16_t DNSLIB_CLASS_CH = 3;	/* Class CHAOS */
//const uint16_t DNSLIB_CLASS_HS = 4;	/* Class HS */
//const uint16_t DNSLIB_CLASS_NONE = 254;	/* Class NONE rfc2136 */
//const uint16_t DNSLIB_CLASS_ANY = 255;	/* Class ANY */

/*
 * Other
 */
static const unsigned int DNSLIB_MAX_DNAME_LENGTH = 255;
static const unsigned int DNSLIB_MAX_DNAME_LABELS = 127;	// 1-char labels

/*
 * RR types in which domain name in RDATA may be compressed.
 */
enum {
	DNSLIB_COMPRESSIBLE_TYPES = 12
};

static const dnslib_rr_type_t
		dnslib_compressible_types[DNSLIB_COMPRESSIBLE_TYPES] = {
	DNSLIB_RRTYPE_NS,
	DNSLIB_RRTYPE_SOA,
	DNSLIB_RRTYPE_CNAME,
	DNSLIB_RRTYPE_PTR,
	DNSLIB_RRTYPE_MB,
	DNSLIB_RRTYPE_MG,
	DNSLIB_RRTYPE_MR,
	DNSLIB_RRTYPE_MINFO,
	DNSLIB_RRTYPE_MX,
	DNSLIB_RRTYPE_AFSDB,
	DNSLIB_RRTYPE_RP,
	DNSLIB_RRTYPE_RT
};

#endif /* _KNOT_DNSLIB_CONSTS_H_ */

/*! @} */
