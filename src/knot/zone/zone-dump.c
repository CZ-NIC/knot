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

#include "knot/zone/zone-dump.h"

#include <config.h>

#include "common/descriptor_new.h"
#include "libknot/libknot.h"

/*! \brief Size of auxiliary buffer. */
#define DUMP_BUF_LEN (70 * 1024)

/*! \brief Dump parameters. */
typedef struct {
	int    ret;
	FILE   *file;
	char   *buf;
	size_t buflen;
	const knot_dname_t *origin;
} dump_params_t;

static void apex_node_dump_text(knot_node_t *node, dump_params_t *params)
{
	knot_rrset_t *rr = knot_node_get_rrset(node, KNOT_RRTYPE_SOA);

	// Dump SOA record as a first.
	if (knot_rrset_txt_dump(rr, params->buf, params->buflen) < 0) {
		params->ret = KNOT_ENOMEM;
		return;
	}
	fprintf(params->file, "%s", params->buf);

	const knot_rrset_t **rrsets = knot_node_rrsets(node);

	// Dump other records.
	for (int i = 0; i < node->rrset_count; i++) {
		if (rrsets[i]->type != KNOT_RRTYPE_SOA) {
			if (knot_rrset_txt_dump(rrsets[i], params->buf,
			                        params->buflen) < 0) {
				params->ret = KNOT_ENOMEM;
				free(rrsets);
				return;
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
	for (int i = 0; i < node->rrset_count; i++) {
		if (knot_rrset_txt_dump(rrsets[i], params->buf, params->buflen)
		    < 0) {
			params->ret = KNOT_ENOMEM;
			free(rrsets);
			return;
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
		return KNOT_ENOMEM;
	}

	fprintf(file, ";; Dumped using Knot DNS %s\n", PACKAGE_VERSION);

	// Set structure with parameters.
	dump_params_t params;
	params.ret = KNOT_ERROR;
	params.file = file;
	params.buf = buf;
	params.buflen = DUMP_BUF_LEN;
	params.origin = knot_node_owner(knot_zone_contents_apex(zone));

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

	return KNOT_EOK;
}
