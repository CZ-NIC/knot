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

#pragma once

#include "libknot/libknot.h"
#include "knot/server/server.h"

#define CMDARGS_ALLOC_BLOCK KNOT_WIRE_MAX_PKTSIZE

#define KNOT_CTL_STATUS			"status"
#define KNOT_CTL_STOP			"stop"
#define KNOT_CTL_RELOAD			"reload"

#define KNOT_CTL_ZONE_STATUS		"zone-status"
#define KNOT_CTL_ZONE_RELOAD		"zone-reload"
#define KNOT_CTL_ZONE_REFRESH		"zone-refresh"
#define KNOT_CTL_ZONE_RETRANSFER	"zone-retransfer"
#define KNOT_CTL_ZONE_FLUSH		"zone-flush"
#define KNOT_CTL_ZONE_SIGN		"zone-sign"

#define KNOT_CTL_CONF_LIST		"conf-list"
#define KNOT_CTL_CONF_READ		"conf-read"
#define KNOT_CTL_CONF_BEGIN		"conf-begin"
#define KNOT_CTL_CONF_COMMIT		"conf-commit"
#define KNOT_CTL_CONF_ABORT		"conf-abort"
#define KNOT_CTL_CONF_DIFF		"conf-diff"
#define KNOT_CTL_CONF_GET		"conf-get"
#define KNOT_CTL_CONF_SET		"conf-set"
#define KNOT_CTL_CONF_UNSET		"conf-unset"

/*! \brief Remote command structure. */
typedef struct {
	const knot_rrset_t *arg;
	unsigned argc;
	knot_rcode_t rc;
	char *response;
	size_t response_size;
	size_t response_max;
} remote_cmdargs_t;

/*! \brief Callback prototype for remote commands. */
typedef int (*remote_cmdf_t)(server_t *, remote_cmdargs_t *);

/*! \brief Remote command table item. */
typedef struct {
	const char *name;
	remote_cmdf_t f;
} remote_cmd_t;

/*! \brief Table of remote commands. */
extern const remote_cmd_t remote_cmd_tbl[];
