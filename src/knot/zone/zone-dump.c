/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <inttypes.h>

#include "knot/dnssec/zone-nsec.h"
#include "knot/zone/skip.h"
#include "knot/zone/zone-dump.h"
#include "libknot/libknot.h"

/*! \brief Size of auxiliary buffer. */
#define DUMP_BUF_LEN (70 * 1024)

/*! \brief Dump parameters. */
typedef struct {
	FILE     *file;
	char     *buf;
	size_t   buflen;
	uint64_t rr_count;
	bool     dump_rrsig;
	bool     dump_nsec;
	zone_skip_t *skip;
	const knot_dname_t *origin;
	const knot_dump_style_t *style;
	const char *first_comment;
} dump_params_t;

static int apex_node_dump_text(zone_node_t *node, dump_params_t *params)
{
	knot_rrset_t soa = node_rrset(node, KNOT_RRTYPE_SOA);

	// Dump SOA record as a first.
	if (!params->dump_nsec && !zone_skip_type(params->skip, KNOT_RRTYPE_SOA)) {
		int ret = knot_rrset_txt_dump(&soa, &params->buf, &params->buflen,
		                              params->style);
		if (ret < 0) {
			return ret;
		}
		params->rr_count += soa.rrs.count;
		if (fprintf(params->file, "%s", params->buf) < 0) {
			return knot_map_errno();
		}
		params->buf[0] = '\0';
	}

	// Dump other records.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (zone_skip_type(params->skip, rrset.type)) {
			continue;
		}
		switch (rrset.type) {
		case KNOT_RRTYPE_NSEC:
			continue;
		case KNOT_RRTYPE_RRSIG:
			continue;
		case KNOT_RRTYPE_SOA:
			continue;
		default:
			break;
		}

		int ret = knot_rrset_txt_dump(&rrset, &params->buf, &params->buflen,
		                              params->style);
		if (ret < 0) {
			return ret;
		}
		params->rr_count +=  rrset.rrs.count;
		if (fprintf(params->file, "%s", params->buf) < 0) {
			return knot_map_errno();
		}
		params->buf[0] = '\0';
	}

	return KNOT_EOK;
}

static int node_dump_text(zone_node_t *node, void *data)
{
	dump_params_t *params = (dump_params_t *)data;

	// Zone apex rrsets.
	if (node->owner == params->origin && !params->dump_rrsig &&
	    !params->dump_nsec) {
		return apex_node_dump_text(node, params);
	}

	// Dump non-apex rrsets.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (zone_skip_type(params->skip, rrset.type)) {
			continue;
		}
		switch (rrset.type) {
		case KNOT_RRTYPE_RRSIG:
			if (params->dump_rrsig) {
				break;
			}
			continue;
		case KNOT_RRTYPE_NSEC:
			if (params->dump_nsec) {
				break;
			}
			continue;
		case KNOT_RRTYPE_NSEC3:
			if (params->dump_nsec) {
				break;
			}
			continue;
		default:
			if (params->dump_nsec || params->dump_rrsig) {
				continue;
			}
			break;
		}

		// Dump block comment if available.
		if (params->first_comment != NULL) {
			if (fprintf(params->file, "%s", params->first_comment) < 0) {
				return knot_map_errno();
			}
			params->first_comment = NULL;
		}

		int ret = knot_rrset_txt_dump(&rrset, &params->buf, &params->buflen,
		                              params->style);
		if (ret < 0) {
			return ret;
		}
		params->rr_count += rrset.rrs.count;
		if (fprintf(params->file, "%s", params->buf) < 0) {
			return knot_map_errno();
		}
		params->buf[0] = '\0';
	}

	return KNOT_EOK;
}

int zone_dump_text(zone_contents_t *zone, zone_skip_t *skip, FILE *file, bool comments, const char *color)
{
	if (file == NULL) {
		return KNOT_EINVAL;
	}

	if (zone == NULL) {
		return KNOT_EEMPTYZONE;
	}

	// Allocate auxiliary buffer for dumping operations.
	char *buf = malloc(DUMP_BUF_LEN);
	if (buf == NULL) {
		return KNOT_ENOMEM;
	}

	if (comments) {
		if (fprintf(file, ";; Zone dump (Knot DNS %s)\n", PACKAGE_VERSION) < 0) {
			return knot_map_errno();
		}
	}

	// Set structure with parameters.
	knot_dump_style_t style = KNOT_DUMP_STYLE_DEFAULT;
	style.color = color;
	style.now = knot_time();
	dump_params_t params = {
		.file = file,
		.buf = buf,
		.buflen = DUMP_BUF_LEN,
		.rr_count = 0,
		.skip = skip,
		.origin = zone->apex->owner,
		.style = &style,
		.dump_rrsig = false,
		.dump_nsec = false
	};

	// Dump standard zone records without RRSIGS.
	int ret = zone_contents_apply(zone, node_dump_text, &params);
	if (ret != KNOT_EOK) {
		free(params.buf);
		return ret;
	}

	// Dump RRSIG records if available.
	params.dump_rrsig = true;
	params.dump_nsec = false;
	params.first_comment = comments ? ";; DNSSEC signatures\n" : NULL;
	ret = zone_contents_apply(zone, node_dump_text, &params);
	if (ret != KNOT_EOK) {
		free(params.buf);
		return ret;
	}

	// Dump NSEC chain if available.
	params.dump_rrsig = false;
	params.dump_nsec = true;
	params.first_comment = comments ? ";; DNSSEC NSEC chain\n" : NULL;
	ret = zone_contents_apply(zone, node_dump_text, &params);
	if (ret != KNOT_EOK) {
		free(params.buf);
		return ret;
	}

	// Dump NSEC3 chain if available.
	params.dump_rrsig = false;
	params.dump_nsec = true;
	params.first_comment = comments ? ";; DNSSEC NSEC3 chain\n" : NULL;
	ret = zone_contents_nsec3_apply(zone, node_dump_text, &params);
	if (ret != KNOT_EOK) {
		free(params.buf);
		return ret;
	}

	params.dump_rrsig = true;
	params.dump_nsec = false;
	params.first_comment = comments ? ";; DNSSEC NSEC3 signatures\n" : NULL;
	ret = zone_contents_nsec3_apply(zone, node_dump_text, &params);
	if (ret != KNOT_EOK) {
		free(params.buf);
		return ret;
	}

	if (comments) {
		// Create formatted date-time string.
		time_t now = time(NULL);
		struct tm tm;
		localtime_r(&now, &tm);
		char date[64];
		strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S %Z", &tm);

		// Dump trailing statistics.
		if (fprintf(file, ";; Written %"PRIu64" records\n"
		                  ";; Time %s\n",
		            params.rr_count, date) < 0) {
			ret = knot_map_errno();
		}
	}

	free(params.buf); // params.buf may be != buf because of knot_rrset_txt_dump_dynamic()

	return ret;
}
