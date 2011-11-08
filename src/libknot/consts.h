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

#include <stdint.h>
#include "util/descriptor.h"

/*
 * OPCODEs
 */
typedef enum knot_opcode {
	KNOT_OPCODE_QUERY  = 0, /* a standard query (QUERY) */
	KNOT_OPCODE_IQUERY = 1, /* an inverse query (IQUERY) */
	KNOT_OPCODE_STATUS = 2, /* a server status request (STATUS) */
	KNOT_OPCODE_NOTIFY = 4, /* NOTIFY */
	KNOT_OPCODE_UPDATE = 5, /* Dynamic update */
	KNOT_OPCODE_OFFSET = 14
} knot_opcode_t;

/*!
 * \brief Query types (internal use only).
 *
 * This type encompasses the different query types distinguished by both the
 * OPCODE and the QTYPE.
 */
typedef enum knot_packet_type {
	KNOT_QUERY_NORMAL,    /*!< Normal query. */
	KNOT_QUERY_AXFR,      /*!< Request for AXFR transfer. */
	KNOT_QUERY_IXFR,      /*!< Request for IXFR transfer. */
	KNOT_QUERY_NOTIFY,    /*!< NOTIFY query. */
	KNOT_QUERY_UPDATE,    /*!< Dynamic update. */
	KNOT_RESPONSE_NORMAL, /*!< Normal response. */
	KNOT_RESPONSE_AXFR,   /*!< AXFR transfer response. */
	KNOT_RESPONSE_IXFR,   /*!< IXFR transfer response. */
	KNOT_RESPONSE_NOTIFY  /*!< NOTIFY response. */
} knot_packet_type_t;

/*
 * RCODEs
 */
typedef enum knot_rcode {
	KNOT_RCODE_NOERROR  = 0,  /* No error condition */
	KNOT_RCODE_FORMERR  = 1,  /* Format error */
	KNOT_RCODE_SERVFAIL = 2,  /* Server failure */
	KNOT_RCODE_NXDOMAIN = 3,  /* Name Error */
	KNOT_RCODE_NOTIMPL  = 4,  /* Not implemented */
	KNOT_RCODE_REFUSED  = 5,  /* Refused */
	KNOT_RCODE_YXDOMAIN = 6,  /* name should not exist */
	KNOT_RCODE_YXRRSET  = 7,  /* rrset should not exist */
	KNOT_RCODE_NXRRSET  = 8,  /* rrset does not exist */
	KNOT_RCODE_NOTAUTH  = 9,  /* server not authoritative */
	KNOT_RCODE_NOTZONE  = 10,  /* name not inside zone */
} knot_rcode_t;

typedef enum knot_tsig_rcode {
	KNOT_TSIG_RCODE_BADSIG  = 16,
	KNOT_TSIG_RCODE_BADKEY  = 17,
	KNOT_TSIG_RCODE_BADTIME = 18
} knot_tsig_rcode_t;

/*
 * CLASSes
 */
//typedef enum knot_class {
//	KNOT_CLASS_IN = 1,	/* Class IN */
//	KNOT_CLASS_CS = 2,	/* Class CS */
//	KNOT_CLASS_CH = 3,	/* Class CHAOS */
//	KNOT_CLASS_HS = 4,	/* Class HS */
//	KNOT_CLASS_NONE = 254,	/* Class NONE rfc2136 */
//	KNOT_CLASS_ANY = 255	/* Class ANY */
//} knot_class_t;

/*
 * Other
 */
typedef enum knot_const {
	KNOT_MAX_DNAME_LENGTH = 255,
	KNOT_MAX_DNAME_LABELS = 127  // 1-char labels
} knot_const_t;

#endif /* _KNOT_CONSTS_H_ */

/*! @} */
