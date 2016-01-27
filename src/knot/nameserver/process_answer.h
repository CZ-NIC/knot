/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief Answer processor.
 *
 * \addtogroup answer_processing
 * @{
 */

#pragma once

#include <sys/socket.h>

#include "knot/conf/conf.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/tsig_ctx.h"

/* Answer processing module implementation. */
const knot_layer_api_t *process_answer_layer(void);
#define KNOT_STATE_ANSWER process_answer_layer()

/*! \brief Answer processing logging base. */
#define ANSWER_LOG(severity, data, operation, msg, ...) \
	NS_PROC_LOG(severity, (data)->param->remote, (data)->param->zone->name, \
	            operation, msg, ##__VA_ARGS__);

/*!
 * \brief Processing module parameters.
 */
struct process_answer_param {
	zone_t *zone;                          /*!< Answer bailiwick. */
	conf_t *conf;                          /*!< Configuration. */
	const knot_pkt_t *query;               /*!< Query preceding the answer. */
	const struct sockaddr_storage *remote; /*!< Answer origin. */
	tsig_ctx_t tsig_ctx;                   /*!< Signing context. */
};

/*!
 * \brief Processing module context.
 */
struct answer_data {
	/* Extensions. */
	void *ext;
	void (*ext_cleanup)(struct answer_data*); /*!< Extensions cleanup callback. */
	knot_sign_context_t sign;            /*!< Signing context. */

	/* Everything below should be kept on reset. */
	int response_type; /*!< Type of incoming response. */
	struct process_answer_param *param; /*!< Module parameters. */
	knot_mm_t *mm;                      /*!< Memory context. */
};

/*! @} */
