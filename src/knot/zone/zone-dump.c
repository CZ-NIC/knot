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

#include <inttypes.h>

#include "knot/zone/zone-dump.h"
#include "libknot/descriptor.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"
#include "knot/dnssec/zone-nsec.h"

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
	const knot_dname_t *origin;
	const knot_dump_style_t *style;
} dump_params_t;

static int apex_node_dump_text(zone_node_t *node, dump_params_t *params)
{
	knot_rrset_t soa = node_rrset(node, KNOT_RRTYPE_SOA);
	knot_dump_style_t soa_style = *params->style;

	// Dump SOA record as a first.
	if (!params->dump_nsec) {
        //char dst[10000];
        //knot_rrset_txt_dump(&soa, dst, 10000,
        //                    &KNOT_DUMP_STYLE_DEFAULT);
        //printf("%s\n", dst);
		if (knot_rrset_txt_dump(&soa, params->buf, params->buflen,
					&soa_style) < 0) {
			return KNOT_ENOMEM;
		}
		params->rr_count += soa.rrs.rr_count;
		fprintf(params->file, "%s", params->buf);
		params->buf[0] = '\0';
	}

	// Dump other records.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
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

        //char dst[10000];
        //knot_rrset_txt_dump(&rrset, dst, 10000,
        //                    &KNOT_DUMP_STYLE_DEFAULT);
        //printf("%s\n", dst);
        
		if (knot_rrset_txt_dump(&rrset, params->buf, params->buflen,
		                        params->style) < 0) {
			return KNOT_ENOMEM;
		}
		params->rr_count +=  rrset.rrs.rr_count;
		fprintf(params->file, "%s", params->buf);
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
		apex_node_dump_text(node, params);
		return KNOT_EOK;
	}

	// Dump non-apex rrsets.
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
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
        case KNOT_RRTYPE_NSEC5:
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
        ////////////////////////////////
        //char dst[10000];
        //knot_rrset_txt_dump(&rrset, dst, 10000,
                            //&KNOT_DUMP_STYLE_DEFAULT);
        //printf("%s\n", dst);
                            
        ////////////////////////////////
        
        
		if (knot_rrset_txt_dump(&rrset, params->buf, params->buflen,
		                        params->style) < 0) {
			return KNOT_ENOMEM;
		}
		params->rr_count += rrset.rrs.rr_count;
		fprintf(params->file, "%s", params->buf);
		params->buf[0] = '\0';
	}

	return KNOT_EOK;
}

int zone_dump_text(zone_contents_t *zone, FILE *file)
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
	zone_node_t *apex = zone->apex;
	dump_params_t params;
	params.file = file;
	params.buf = buf;
	params.buflen = DUMP_BUF_LEN;
	params.rr_count = 0;
	params.origin = apex->owner;
	params.style = &KNOT_DUMP_STYLE_DEFAULT;

	int ret;

	// Dump standard zone records without rrsigs.
	params.dump_rrsig = false;
	params.dump_nsec = false;
	ret = zone_contents_tree_apply_inorder(zone, node_dump_text, &params);
	if (ret != KNOT_EOK) {
		return ret;
	}

    //printf("standart zone records done\n");
	// Dump DNSSEC signatures if secured.
	if (zone_contents_is_signed(zone)) {
		fprintf(file, ";; DNSSEC signatures\n");

		// Dump rrsig records.
		params.dump_rrsig = true;
		params.dump_nsec = false;
		ret = zone_contents_tree_apply_inorder(zone, node_dump_text,
		                                       &params);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

    //printf("dnssec signature records done\n");
    bool nsec3 = knot_is_nsec3_enabled(zone);
    bool nsec5 = knot_is_nsec5_enabled(zone);

	// Dump NSEC3/NSEC5 chain if available.
	if ( nsec3|| nsec5) {
        //keep boths checks separate for easier error detection from journal
        if (nsec3) {
            fprintf(file, ";; DNSSEC NSEC3 chain\n");
        }
        if (nsec5) {
            fprintf(file, ";; DNSSEC NSEC5 chain\n");
        }

		params.dump_rrsig = false;
		params.dump_nsec = true;
		ret = zone_contents_nsec3_apply_inorder(zone, node_dump_text,
		                                        &params);
		if (ret != KNOT_EOK) {
			return ret;
		}

        if (nsec3) {
            fprintf(file, ";; DNSSEC NSEC3 signatures\n");
        }
        if (nsec5) {
            fprintf(file, ";; DNSSEC NSEC5 signatures\n");
        }
        
		params.dump_rrsig = true;
		params.dump_nsec = false;
		ret = zone_contents_nsec3_apply_inorder(zone, node_dump_text,
		                                        &params);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else if (zone_contents_is_signed(zone)) {
		fprintf(file, ";; DNSSEC NSEC chain\n");

		// Dump nsec records.
		params.dump_rrsig = false;
		params.dump_nsec = true;
		ret = zone_contents_tree_apply_inorder(zone, node_dump_text,
		                                       &params);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

    //printf("nsec chain records done\n");
    
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

	free(buf);

	return KNOT_EOK;
}
