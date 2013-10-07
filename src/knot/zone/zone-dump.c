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

#include <config.h>
#include <inttypes.h>

#include "knot/zone/zone-dump.h"
#include "common/descriptor.h"
#include "knot/conf/conf.h"
#include "knot/server/zones.h"
#include "libknot/libknot.h"

/*! \brief Size of auxiliary buffer. */
#define DUMP_BUF_LEN (70 * 1024)

/*! \brief Dump parameters. */
typedef struct {
	int      ret;
	FILE     *file;
	char     *buf;
	size_t   buflen;
	uint64_t rr_count;
	const knot_dname_t *origin;
	const knot_dump_style_t *style;
} dump_params_t;

static void apex_node_dump_text(knot_node_t *node, dump_params_t *params)
{
	knot_rrset_t *rr = knot_node_get_rrset(node, KNOT_RRTYPE_SOA);

	// Dump SOA record as a first.
	if (knot_rrset_txt_dump(rr, params->buf, params->buflen,
	                        params->style) < 0) {
		params->ret = KNOT_ENOMEM;
		return;
	}
	params->rr_count += rr->rdata_count;
	if (rr->rrsigs != NULL) {
		params->rr_count += rr->rrsigs->rdata_count;
	}
	fprintf(params->file, "%s", params->buf);

	const knot_rrset_t **rrsets = knot_node_rrsets(node);

	// Dump other records.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		if (rrsets[i]->type != KNOT_RRTYPE_SOA) {
			if (knot_rrset_txt_dump(rrsets[i], params->buf,
			                        params->buflen, params->style)
			    < 0) {
				params->ret = KNOT_ENOMEM;
				free(rrsets);
				return;
			}
			params->rr_count += rrsets[i]->rdata_count;
			if (rrsets[i]->rrsigs != NULL) {
				params->rr_count +=
					rrsets[i]->rrsigs->rdata_count;
			}
			fprintf(params->file, "%s", params->buf);
		}
	}

	free(rrsets);

	params->ret = KNOT_EOK;
}

static void node_dump_text(knot_node_t *node, void *data)
{
	dump_params_t *params = (dump_params_t *)data;

	// Zone apex rrsets.
	if (node->owner == params->origin) {
		apex_node_dump_text(node, params);
		return;
	}

	const knot_rrset_t **rrsets = knot_node_rrsets(node);

	// Dump non-apex rrsets.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		if (knot_rrset_txt_dump(rrsets[i], params->buf, params->buflen,
		                        params->style) < 0) {
			params->ret = KNOT_ENOMEM;
			free(rrsets);
			return;
		}
		params->rr_count += rrsets[i]->rdata_count;
		if (rrsets[i]->rrsigs != NULL) {
			params->rr_count += rrsets[i]->rrsigs->rdata_count;
		}
		fprintf(params->file, "%s", params->buf);
	}

	free(rrsets);

	params->ret = KNOT_EOK;
}

int zone_dump_text(knot_zone_contents_t *zone, FILE *file)
{
	if (zone == NULL || file == NULL) {
		return KNOT_EINVAL;
	}

	// Allocate auxiliary buffer for dumping operations.
	char *buf = malloc(DUMP_BUF_LEN);
	if (buf == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	fprintf(file, ";; Zone dump (Knot DNS %s)\n", PACKAGE_VERSION);

	// Set structure with parameters.
	dump_params_t params;
	params.ret = KNOT_ERROR;
	params.file = file;
	params.buf = buf;
	params.buflen = DUMP_BUF_LEN;
	params.rr_count = 0;
	params.origin = knot_node_owner(knot_zone_contents_apex(zone));
	params.style = &KNOT_DUMP_STYLE_DEFAULT;

	// Dump standard zone records.
	knot_zone_contents_tree_apply_inorder(zone, node_dump_text, &params);
	if (params.ret != KNOT_EOK) {
		return params.ret;
	}

	// Dump NSEC3 zone records.
	knot_zone_contents_nsec3_apply_inorder(zone, node_dump_text, &params);
	if (params.ret != KNOT_EOK) {
		return params.ret;
	}

	// Create formated date-time string.
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	char date[64];
	strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S %Z", &tm);

	// Dump trailing statistics.
	fprintf(file, ";; Written %"PRIu64" records\n"
	              ";; Time %s\n",
	        params.rr_count, date);

	// Get master information.
	sockaddr_t *master = &((zonedata_t *)zone->zone->data)->xfr_in.master;

	int port = sockaddr_portnum(master);

	// If a master server is configured, dump info about it.
	if (port >= 0) {
		char addr[INET6_ADDRSTRLEN] = "NULL";
		sockaddr_tostr(master, addr, sizeof(addr));

		fprintf(file, ";; Transfered from %s#%i\n", addr, port);
	}

	free(buf);

	return KNOT_EOK;
}
