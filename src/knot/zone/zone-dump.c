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
#include "libknot/dnssec/zone-nsec.h"

/*! \brief Size of auxiliary buffer. */
#define DUMP_BUF_LEN (70 * 1024)

/*! \brief Dump parameters. */
typedef struct {
	FILE     *file;
	char     *buf;
	size_t   buflen;
	uint64_t rr_count;
	bool     dump_rdata;
	bool     dump_rrsig;
	bool     dump_nsec;
	const knot_dname_t *origin;
	const knot_dump_style_t *style;
} dump_params_t;

static int apex_node_dump_text(knot_node_t *node, dump_params_t *params)
{
	const knot_rrset_t *soa = knot_node_rrset(node, KNOT_RRTYPE_SOA);

	knot_dump_style_t soa_style = *params->style;

	// Dump SOA record as a first.
	if (!params->dump_nsec) {
		if (params->dump_rdata) {
			soa_style.show_class = true;
		}
		if (knot_rrset_txt_dump(soa, params->buf, params->buflen,
					params->dump_rdata, params->dump_rrsig,
					&soa_style) < 0) {
			return KNOT_ENOMEM;
		}
		if (params->dump_rdata) {
			params->rr_count += soa->rdata_count;
		}
		if (params->dump_rrsig && soa->rrsigs != NULL) {
			params->rr_count += soa->rrsigs->rdata_count;
		}
		fprintf(params->file, "%s", params->buf);
		params->buf[0] = '\0';
	}

	const knot_rrset_t **rrsets = knot_node_rrsets_no_copy(node);

	// Dump other records.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		switch (rrsets[i]->type) {
		case KNOT_RRTYPE_NSEC:
			if (params->dump_nsec) {
				break;
			}
			continue;
		case KNOT_RRTYPE_SOA:
			continue;
		default:
			if (params->dump_nsec) {
				continue;
			}
			break;
		}

		if (knot_rrset_txt_dump(rrsets[i], params->buf, params->buflen,
		                        params->dump_rdata, params->dump_rrsig,
		                        params->style) < 0) {
			return KNOT_ENOMEM;
		}
		if (params->dump_rdata) {
			params->rr_count += rrsets[i]->rdata_count;
		}
		if (params->dump_rrsig && rrsets[i]->rrsigs != NULL) {
			params->rr_count += rrsets[i]->rrsigs->rdata_count;
		}
		fprintf(params->file, "%s", params->buf);
		params->buf[0] = '\0';
	}

	return KNOT_EOK;
}

static int node_dump_text(knot_node_t *node, void *data)
{
	dump_params_t *params = (dump_params_t *)data;

	// Zone apex rrsets.
	if (node->owner == params->origin) {
		apex_node_dump_text(node, params);
		return KNOT_EOK;
	}

	const knot_rrset_t **rrsets = knot_node_rrsets_no_copy(node);

	// Dump non-apex rrsets.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		switch (rrsets[i]->type) {
		case KNOT_RRTYPE_NSEC:
			if (params->dump_nsec) {
				break;
			}
			continue;
		default:
			if (params->dump_nsec) {
				continue;
			}
			break;
		}

		if (knot_rrset_txt_dump(rrsets[i], params->buf, params->buflen,
		                        params->dump_rdata, params->dump_rrsig,
		                        params->style) < 0) {
			return KNOT_ENOMEM;
		}
		if (params->dump_rdata) {
			params->rr_count += rrsets[i]->rdata_count;
		}
		if (params->dump_rrsig && rrsets[i]->rrsigs != NULL) {
			params->rr_count += rrsets[i]->rrsigs->rdata_count;
		}
		fprintf(params->file, "%s", params->buf);
		params->buf[0] = '\0';
	}

	return KNOT_EOK;
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
	params.file = file;
	params.buf = buf;
	params.buflen = DUMP_BUF_LEN;
	params.rr_count = 0;
	params.origin = knot_node_owner(knot_zone_contents_apex(zone));
	params.style = &KNOT_DUMP_STYLE_DEFAULT;

	int ret;

	// Dump standard zone records without rrsigs.
	params.dump_rdata = true;
	params.dump_rrsig = false;
	params.dump_nsec = false;
	ret = knot_zone_contents_tree_apply_inorder(zone, node_dump_text, &params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Dump DNSSEC signatures if secured.
	const knot_rrset_t *soa = knot_node_rrset(knot_zone_contents_apex(zone),
	                                          KNOT_RRTYPE_SOA);
	if (soa && soa->rrsigs) {
		fprintf(file, ";; DNSSEC signatures\n");

		// Dump rrsig records.
		params.dump_rdata = false;
		params.dump_rrsig = true;
		params.dump_nsec = false;
		ret = knot_zone_contents_tree_apply_inorder(zone, node_dump_text,
		                                            &params);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Dump NSEC3 chain if available.
	if (is_nsec3_enabled(zone)) {
		fprintf(file, ";; DNSSEC NSEC3 chain\n");

		params.dump_rdata = true;
		params.dump_rrsig = true;
		params.dump_nsec = false;
		ret = knot_zone_contents_nsec3_apply_inorder(zone, node_dump_text,
		                                             &params);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else if (soa && soa->rrsigs) {
		fprintf(file, ";; DNSSEC NSEC chain\n");

		// Dump nsec and rrsig records.
		params.dump_rdata = true;
		params.dump_rrsig = true;
		params.dump_nsec = true;
		ret = knot_zone_contents_tree_apply_inorder(zone, node_dump_text,
		                                            &params);
		if (ret != KNOT_EOK) {
			return ret;
		}
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
