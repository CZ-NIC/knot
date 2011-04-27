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
typedef enum dnslib_opcode {
	DNSLIB_OPCODE_QUERY  = 0, /* a standard query (QUERY) */
	DNSLIB_OPCODE_IQUERY = 1, /* an inverse query (IQUERY) */
	DNSLIB_OPCODE_STATUS = 2, /* a server status request (STATUS) */
	DNSLIB_OPCODE_NOTIFY = 4, /* NOTIFY */
	DNSLIB_OPCODE_UPDATE = 5, /* Dynamic update */
	DNSLIB_OPCODE_OFFSET = 14
} dnslib_opcode_t;

/*!
 * \brief Query types (internal use only).
 *
 * This type encompasses the different query types distinguished by both the
 * OPCODE and the QTYPE.
 */
typedef enum dnslib_packet_type {
	DNSLIB_QUERY_NORMAL,    /*!< Normal query. */
	DNSLIB_QUERY_AXFR,      /*!< Request for AXFR transfer. */
	DNSLIB_QUERY_IXFR,      /*!< Request for IXFR transfer. */
	DNSLIB_QUERY_NOTIFY,    /*!< NOTIFY query. */
	DNSLIB_QUERY_UPDATE,    /*!< Dynamic update. */
	DNSLIB_RESPONSE_NORMAL, /*!< Normal response. */
	DNSLIB_RESPONSE_AXFR,   /*!< AXFR transfer response. */
	DNSLIB_RESPONSE_IXFR,   /*!< IXFR transfer response. */
	DNSLIB_RESPONSE_NOTIFY  /*!< NOTIFY response. */
} dnslib_packet_type_t;

/*
 * RCODEs
 */
typedef enum dnslib_rcode {
	DNSLIB_RCODE_NOERROR  = 0,  /* No error condition */
	DNSLIB_RCODE_FORMERR  = 1,  /* Format error */
	DNSLIB_RCODE_SERVFAIL = 2,  /* Server failure */
	DNSLIB_RCODE_NXDOMAIN = 3,  /* Name Error */
	DNSLIB_RCODE_NOTIMPL  = 4,  /* Not implemented */
	DNSLIB_RCODE_REFUSED  = 5,  /* Refused */
	DNSLIB_RCODE_YXDOMAIN = 6,  /* name should not exist */
	DNSLIB_RCODE_YXRRSET  = 7,  /* rrset should not exist */
	DNSLIB_RCODE_NXRRSET  = 8,  /* rrset does not exist */
	DNSLIB_RCODE_NOTAUTH  = 9,  /* server not authoritative */
	DNSLIB_RCODE_NOTZONE  = 10  /* name not inside zone */
} dnslib_rcode_t;

/*
 * CLASSes
 */
//typedef enum dnslib_class {
//	DNSLIB_CLASS_IN = 1,	/* Class IN */
//	DNSLIB_CLASS_CS = 2,	/* Class CS */
//	DNSLIB_CLASS_CH = 3,	/* Class CHAOS */
//	DNSLIB_CLASS_HS = 4,	/* Class HS */
//	DNSLIB_CLASS_NONE = 254,	/* Class NONE rfc2136 */
//	DNSLIB_CLASS_ANY = 255	/* Class ANY */
//} dnslib_class_t;

/*
 * Other
 */
typedef enum dnslib_const {
	DNSLIB_MAX_DNAME_LENGTH = 255,
	DNSLIB_MAX_DNAME_LABELS = 127  // 1-char labels
} dnslib_const_t;

#endif /* _KNOT_DNSLIB_CONSTS_H_ */

/*! @} */
