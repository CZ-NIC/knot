/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/nameserver/process_query.h"

/* Query processing module implementation. */
extern const knot_process_module_t _process_answer;
#define NS_PROC_ANSWER (&_process_answer)
#define NS_PROC_ANSWER_ID 2

/*! \brief Answer processsing logging base. */
#define ANSWER_LOG(severity, data, what, msg...) do {\
	const char *zone_str = (data)->param->zone->conf->name; \
	NS_PROC_LOG(severity, LOG_SERVER, (data)->param->remote, zone_str, \
	            what " of '%s' from '%s': ", msg); \
	} while(0)


/* Module load parameters. */
struct process_answer_param {
	zone_t   *zone;
	const knot_pkt_t *query;
	const struct sockaddr_storage *remote;
};

struct answer_data
{
	/* Extensions. */
	void *ext;
	void (*ext_cleanup)(struct answer_data*); /*!< Extensions cleanup callback. */
	knot_sign_context_t sign;            /*!< Signing context. */

	/* Everything below should be kept on reset. */
	struct process_answer_param *param; /*!< Module parameters. */
	mm_ctx_t *mm;                      /*!< Memory context. */
};

/*!
 * \brief Initialize answer processing context.
 *
 * \param ctx
 * \param module_param
 * \return MORE (awaits answer)
 */
int process_answer_begin(knot_process_t *ctx, void *module_param);

/*!
 * \brief Reset answer processing context.
 *
 * \param ctx
 * \return MORE (awaits next answer)
 */
int process_answer_reset(knot_process_t *ctx);

/*!
 * \brief Finish and close current answer processing.
 *
 * \param ctx
 * \return NOOP (context will be inoperable further on)
 */
int process_answer_finish(knot_process_t *ctx);

/*!
 * \brief Process single answer packet.
 *
 * \param pkt
 * \param ctx
 * \retval NOOP (unsupported answer)
 * \return MORE (awaits next answer)
 * \retval DONE (processing finished)
 * \retval FAIL (processing failed)
 */
int process_answer(knot_pkt_t *pkt, knot_process_t *ctx);
