/*!
 * \file zoneparser.h
 *
 * \author modifications by Jan Kadlec <jan.kadlec@nic.cz>, most of the code
 *         by NLnet Labs.
 *         Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * \brief Zone compiler.
 *
 * \addtogroup zoneparser
 * @{
 */

/*
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _KNOTD_ZONEPARSER_H_
#define _KNOTD_ZONEPARSER_H_

#include <stdio.h>

#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/zone/node.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/dname-table.h"
#include "libknot/zone/dname-table.h"
#include "common/slab/slab.h"

#define MAXRDATALEN	64	/*!< Maximum number of RDATA items. */
#define MAXLABELLEN	63	/*!< Maximum label length. */
#define MAXDOMAINLEN	255	/*!< Maximum domain name length */
#define MAX_RDLENGTH	65535	/*!< Maximum length of RDATA item */
#define	MAXTOKENSLEN	512	/*!< Maximum number of tokens per entry. */
#define	B64BUFSIZE	65535	/*!< Buffer size for b64 conversion. */
#define	ROOT		(const uint8_t *)"\001" /*!< Root domain name. */

#define NSEC_WINDOW_COUNT     256	/*!< Number of NSEC windows. */
#define NSEC_WINDOW_BITS_COUNT 256	/*!< Number of bits in NSEC window. */
/*! \brief Size of NSEC window in bytes. */
#define NSEC_WINDOW_BITS_SIZE  (NSEC_WINDOW_BITS_COUNT / 8)

/*
 * RFC 4025 - codes for different types that IPSECKEY can hold.
 */
#define IPSECKEY_NOGATEWAY      0
#define IPSECKEY_IP4            1
#define IPSECKEY_IP6            2
#define IPSECKEY_DNAME          3

#define LINEBUFSZ 1024	/*!< Buffer size for one line in zone file. */

struct lex_data {
    size_t   len;		/*!< holds the label length */
    char    *str;		/*!< holds the data */
};

#define DEFAULT_TTL 3600

/*! \todo Implement ZoneDB. */
typedef void namedb_type;

/*!
 * \brief One-purpose linked list holding pointers to RRSets.
 */
struct rrset_list {
	knot_rrset_t *data; /*!< List data. */
	struct rrset_list *next; /*!< Next node. */
};

typedef struct rrset_list rrset_list_t;

/*!
 * \brief Parses and creates zone from given file.
 *
 * \param name Origin domain name string.
 * \param zonefile File containing the zone.
 * \param outfile File to save dump of the zone to.
 * \param semantic_checks Enables or disables sematic checks.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int zone_read(const char *name, const char *zonefile, int semantic_checks,
              knot_zone_t **out_zone);

#endif /* _KNOTD_ZONEPARSER_H_ */

/*! @} */
