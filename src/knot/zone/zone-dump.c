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

#define DUMP_BUF_LEN (70 * 1024)

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

	int ret = knot_rrset_txt_dump(rr, params->buf, params->buflen);
	if (ret < 0) {
		params->ret = KNOT_ENOMEM;
		return;
	}
	fprintf(params->file, "%s", params->buf);

	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	
	for (int i = 0; i < node->rrset_count; i++) {
		if (rrsets[i]->type != KNOT_RRTYPE_SOA) {
			ret = knot_rrset_txt_dump(rrsets[i], params->buf,
			                          params->buflen);
			if (ret < 0) {
				free(rrsets);
				params->ret = KNOT_ENOMEM;
				return;
			}
			fprintf(params->file, "%s", params->buf);
		}
	}

	free(rrsets);

	params->ret = KNOT_EOK;
}

void node_dump_text(knot_node_t *node, void *data)
{
	dump_params_t *params = (dump_params_t *)data;

	if (node->owner == params->origin) {
		apex_node_dump_text(node, params);
		return;
	}

	const knot_rrset_t **rrsets = knot_node_rrsets(node);

	int ret;
	for (int i = 0; i < node->rrset_count; i++) {
		ret = knot_rrset_txt_dump(rrsets[i], params->buf, params->buflen);
		if (ret < 0) {
			params->ret = KNOT_ENOMEM;
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

	char *buf = malloc(DUMP_BUF_LEN);
	if (buf == NULL) {
		return KNOT_ENOMEM;
	}

	fprintf(file, ";Dumped using %s v. %s\n", PACKAGE_NAME, PACKAGE_VERSION);

	dump_params_t params;
	params.ret = KNOT_ERROR;
	params.file = file;
	params.buf = buf;
	params.buflen = DUMP_BUF_LEN;
	params.origin = knot_node_owner(knot_zone_contents_apex(zone));

	knot_zone_contents_tree_apply_inorder(zone, node_dump_text, &params);
	if (params.ret != KNOT_EOK) {
		return params.ret;
	}

	knot_zone_contents_nsec3_apply_inorder(zone, node_dump_text, &params);
	if (params.ret != KNOT_EOK) {
		return params.ret;
	}

	return KNOT_EOK;
}
