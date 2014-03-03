/*!
 * \file synth_record.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Synthetic records
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _SYNTH_RECORD_H

#include "knot/nameserver/process_query.h"
#include "knot/updates/acl.h"
#include "common/lists.h"

/*! \brief Supported answer synthesis template types. */
enum synth_template_type {
	SYNTH_FORWARD,
	SYNTH_REVERSE
};

/*!
 * \brief Synthetic response template.
 */
typedef struct synth_template {
	node_t node;
	enum synth_template_type type;
	char *format;
	uint32_t ttl;
	netblock_t subnet;
} synth_template_t;

/*!
 * \brief Return true if it is possible to synthetize response.
 * \param qdata
 */
bool synth_answer_possible(struct query_data *qdata);

/*!
 * \brief Attempt to synthetize response.
 * \param pkt
 * \param qdata
 * \return EOK if success, else error code
 */
int synth_answer(knot_pkt_t *pkt, struct query_data *qdata);

#define _SYNTH_RECORD_H

#endif /* _SYNTH_RECORD_H */

/*! @} */
