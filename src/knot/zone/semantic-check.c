/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#include "knot/zone/semantic-check.h"

#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "contrib/string.h"
#include "libknot/libknot.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/updates/zone-update.h"

static const char *error_messages[SEM_ERR_UNKNOWN + 1] = {
	[SEM_ERR_SOA_NONE] =
	"missing SOA at the zone apex",

	[SEM_ERR_CNAME_EXTRA_RECORDS] =
	"another record exists beside CNAME",
	[SEM_ERR_CNAME_MULTIPLE] =
	"multiple CNAME records",

	[SEM_ERR_DNAME_CHILDREN] =
	"child record exists under DNAME",
	[SEM_ERR_DNAME_MULTIPLE] =
	"multiple DNAME records",
	[SEM_ERR_DNAME_EXTRA_NS] =
	"NS record exists beside DNAME",

	[SEM_ERR_NS_APEX] =
	"missing NS at the zone apex",
	[SEM_ERR_NS_GLUE] =
	"missing glue record",

	[SEM_ERR_RRSIG_UNVERIFIABLE] =
	"no valid signature for a record",

	[SEM_ERR_NSEC_NONE] =
	"missing NSEC(3) record",
	[SEM_ERR_NSEC_RDATA_BITMAP] =
	"wrong NSEC(3) bitmap",
	[SEM_ERR_NSEC_RDATA_CHAIN] =
	"inconsistent NSEC(3) chain",
	[SEM_ERR_NSEC3_INSECURE_DELEGATION_OPT] =
	"wrong NSEC3 opt-out",

	[SEM_ERR_NSEC3PARAM_RDATA_FLAGS] =
	"invalid flags in NSEC3PARAM",
	[SEM_ERR_NSEC3PARAM_RDATA_ALG] =
	"invalid algorithm in NSEC3PARAM",

	[SEM_ERR_DS_RDATA_ALG] =
	"invalid algorithm in DS",
	[SEM_ERR_DS_RDATA_DIGLEN] =
	"invalid digest length in DS",

	[SEM_ERR_DNSKEY_NONE] =
	"missing DNSKEY",
	[SEM_ERR_DNSKEY_INVALID] =
	"invalid DNSKEY",

	[SEM_ERR_CDS_NONE] =
	"missing CDS",
	[SEM_ERR_CDS_NOT_MATCH] =
	"CDS not match CDNSKEY",

	[SEM_ERR_CDNSKEY_NONE] =
	"missing CDNSKEY",
	[SEM_ERR_CDNSKEY_NO_DNSKEY] =
	"CDNSKEY not match DNSKEY",
	[SEM_ERR_CDNSKEY_NO_CDS] =
	"CDNSKEY without corresponding CDS",
	[SEM_ERR_CDNSKEY_INVALID_DELETE] =
	"invalid CDNSKEY/CDS for DNSSEC delete algorithm",

	[SEM_ERR_UNKNOWN] =
	"unknown error"
};

const char *sem_error_msg(sem_error_t code)
{
	if (code > SEM_ERR_UNKNOWN) {
		code = SEM_ERR_UNKNOWN;
	}
	return error_messages[code];
}

typedef enum {
	MANDATORY = 1 << 0,
	SOFT      = 1 << 1,
	OPTIONAL  = 1 << 2,
	DNSSEC    = 1 << 3,
} check_level_t;

typedef struct {
	zone_contents_t *zone;
	sem_handler_t *handler;
	check_level_t level;
	time_t time;
} semchecks_data_t;

static int check_soa(const zone_node_t *node, semchecks_data_t *data);
static int check_cname(const zone_node_t *node, semchecks_data_t *data);
static int check_dname(const zone_node_t *node, semchecks_data_t *data);
static int check_delegation(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3param(const zone_node_t *node, semchecks_data_t *data);
static int check_submission(const zone_node_t *node, semchecks_data_t *data);
static int check_ds(const zone_node_t *node, semchecks_data_t *data);

struct check_function {
	int (*function)(const zone_node_t *, semchecks_data_t *);
	check_level_t level;
};

static const struct check_function CHECK_FUNCTIONS[] = {
	{ check_soa,            MANDATORY },
	{ check_cname,          MANDATORY | SOFT },
	{ check_dname,          MANDATORY | SOFT },
	{ check_delegation,     MANDATORY | SOFT }, // mandatory for apex, optional for others
	{ check_ds,             OPTIONAL },
	{ check_nsec3param,     DNSSEC },
	{ check_submission,     DNSSEC },
};

static const int CHECK_FUNCTIONS_LEN = sizeof(CHECK_FUNCTIONS)
                                     / sizeof(struct check_function);

static int check_delegation(const zone_node_t *node, semchecks_data_t *data)
{
	if (!((node->flags & NODE_FLAGS_DELEG) || data->zone->apex == node)) {
		return KNOT_EOK;
	}

	// always check zone apex
	if (!(data->level & OPTIONAL) && data->zone->apex != node) {
		return KNOT_EOK;
	}

	const knot_rdataset_t *ns_rrs = node_rdataset(node, KNOT_RRTYPE_NS);
	if (ns_rrs == NULL) {
		assert(data->zone->apex == node);
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_NS_APEX, NULL);
		return KNOT_EOK;
	}

	// check glue record for delegation
	for (int i = 0; i < ns_rrs->count; ++i) {
		knot_rdata_t *ns_rr = knot_rdataset_at(ns_rrs, i);
		const knot_dname_t *ns_dname = knot_ns_name(ns_rr);
		const zone_node_t *glue_node = NULL, *glue_encloser = NULL;
		int ret = zone_contents_find_dname(data->zone, ns_dname, &glue_node,
		                                   &glue_encloser, NULL);
		switch (ret) {
		case KNOT_EOUTOFZONE:
			continue; // NS is out of bailiwick
		case ZONE_NAME_NOT_FOUND:
			if (glue_encloser != node &&
			    glue_encloser->flags & (NODE_FLAGS_DELEG | NODE_FLAGS_NONAUTH)) {
				continue; // NS is below another delegation
			}

			// check if covered by wildcard
			knot_dname_storage_t wildcard = "\x01""*";
			knot_dname_to_wire(wildcard + 2, glue_encloser->owner,
			                   sizeof(wildcard) - 2);
			glue_node = zone_contents_find_node(data->zone, wildcard);
			break; // continue in checking glue existence
		case ZONE_NAME_FOUND:
			break; // continue in checking glue existence
		default:
			return ret;
		}
		if (!node_rrtype_exists(glue_node, KNOT_RRTYPE_A) &&
		    !node_rrtype_exists(glue_node, KNOT_RRTYPE_AAAA)) {
			data->handler->cb(data->handler, data->zone, node->owner,
			                  SEM_ERR_NS_GLUE, NULL);
		}
	}

	return KNOT_EOK;
}

static int check_submission(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *cdss = node_rdataset(node, KNOT_RRTYPE_CDS);
	const knot_rdataset_t *cdnskeys = node_rdataset(node, KNOT_RRTYPE_CDNSKEY);
	if (cdss == NULL && cdnskeys == NULL) {
		return KNOT_EOK;
	} else if (cdss == NULL) {
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_CDS_NONE, NULL);
		return KNOT_EOK;
	} else if (cdnskeys == NULL) {
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_CDNSKEY_NONE, NULL);
		return KNOT_EOK;
	}

	const knot_rdataset_t *dnskeys = node_rdataset(data->zone->apex,
	                                               KNOT_RRTYPE_DNSKEY);
	if (dnskeys == NULL) {
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_DNSKEY_NONE, NULL);
	}

	const uint8_t *empty_cds = (uint8_t *)"\x00\x00\x00\x00\x00";
	const uint8_t *empty_cdnskey = (uint8_t *)"\x00\x00\x03\x00\x00";
	bool delete_cds = false, delete_cdnskey = false;

	// check every CDNSKEY for corresponding DNSKEY
	for (int i = 0; i < cdnskeys->count; i++) {
		knot_rdata_t *cdnskey = knot_rdataset_at(cdnskeys, i);

		// skip delete-dnssec CDNSKEY
		if (cdnskey->len == 5 && memcmp(cdnskey->data, empty_cdnskey, 5) == 0) {
			delete_cdnskey = true;
			continue;
		}

		bool match = false;
		for (int j = 0; dnskeys != NULL && j < dnskeys->count; j++) {
			knot_rdata_t *dnskey = knot_rdataset_at(dnskeys, j);

			if (knot_rdata_cmp(dnskey, cdnskey) == 0) {
				match = true;
				break;
			}
		}
		if (!match) {
			data->handler->cb(data->handler, data->zone, node->owner,
			                  SEM_ERR_CDNSKEY_NO_DNSKEY, NULL);
		}
	}

	// check every CDS for corresponding CDNSKEY
	for (int i = 0; i < cdss->count; i++) {
		knot_rdata_t *cds = knot_rdataset_at(cdss, i);
		uint8_t digest_type = knot_ds_digest_type(cds);

		// skip delete-dnssec CDS
		if (cds->len == 5 && memcmp(cds->data, empty_cds, 5) == 0) {
			delete_cds = true;
			continue;
		}

		bool match = false;
		for (int j = 0; j < cdnskeys->count; j++) {
			knot_rdata_t *cdnskey = knot_rdataset_at(cdnskeys, j);

			dnssec_key_t *key;
			int ret = dnssec_key_from_rdata(&key, data->zone->apex->owner,
			                                cdnskey->data, cdnskey->len);
			if (ret != KNOT_EOK) {
				continue;
			}

			dnssec_binary_t cds_calc = { 0 };
			dnssec_binary_t cds_orig = { .size = cds->len, .data = cds->data };
			ret = dnssec_key_create_ds(key, digest_type, &cds_calc);
			if (ret != KNOT_EOK) {
				dnssec_key_free(key);
				return ret;
			}

			ret = dnssec_binary_cmp(&cds_orig, &cds_calc);
			dnssec_binary_free(&cds_calc);
			dnssec_key_free(key);
			if (ret == 0) {
				match = true;
				break;
			}
		}
		if (!match) {
			data->handler->cb(data->handler, data->zone, node->owner,
			                  SEM_ERR_CDS_NOT_MATCH, NULL);
		}
	}

	// check delete-dnssec records
	if ((delete_cds && (!delete_cdnskey || cdss->count > 1)) ||
	    (delete_cdnskey && (!delete_cds || cdnskeys->count > 1))) {
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_CDNSKEY_INVALID_DELETE, NULL);
	}

	// check orphaned CDS
	if (cdss->count < cdnskeys->count) {
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_CDNSKEY_NO_CDS, NULL);
	}

	return KNOT_EOK;
}

static int check_ds(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *dss = node_rdataset(node, KNOT_RRTYPE_DS);
	if (dss == NULL) {
		return KNOT_EOK;
	}

	for (int i = 0; i < dss->count; i++) {
		knot_rdata_t *ds = knot_rdataset_at(dss, i);
		uint16_t keytag = knot_ds_key_tag(ds);
		uint8_t digest_type = knot_ds_digest_type(ds);

		char info[64] = "";
		(void)snprintf(info, sizeof(info), "(keytag %d)", keytag);

		if (!dnssec_algorithm_digest_support(digest_type)) {
			data->handler->cb(data->handler, data->zone, node->owner,
			                  SEM_ERR_DS_RDATA_ALG, info);
		} else {
			// Sizes for different digest algorithms.
			const uint16_t digest_sizes [] = { 0, 20, 32, 32, 48};

			uint16_t digest_size = knot_ds_digest_len(ds);

			if (digest_sizes[digest_type] != digest_size) {
				data->handler->cb(data->handler, data->zone, node->owner,
				                  SEM_ERR_DS_RDATA_DIGLEN, info);
			}
		}
	}

	return KNOT_EOK;
}

static int check_soa(const zone_node_t *node, semchecks_data_t *data)
{
	if (data->zone->apex != node) {
		return KNOT_EOK;
	}

	const knot_rdataset_t *soa_rrs = node_rdataset(node, KNOT_RRTYPE_SOA);
	if (soa_rrs == NULL) {
		data->handler->error = true;
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_SOA_NONE, NULL);
	}

	return KNOT_EOK;
}

static int check_cname(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *cname_rrs = node_rdataset(node, KNOT_RRTYPE_CNAME);
	if (cname_rrs == NULL) {
		return KNOT_EOK;
	}

	unsigned rrset_limit = 1;
	/* With DNSSEC node can contain RRSIGs or NSEC */
	if (node_rrtype_exists(node, KNOT_RRTYPE_NSEC)) {
		rrset_limit += 1;
	}
	if (node_rrtype_exists(node, KNOT_RRTYPE_RRSIG)) {
		rrset_limit += 1;
	}

	if (node->rrset_count > rrset_limit) {
		data->handler->error = true;
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_CNAME_EXTRA_RECORDS, NULL);
	}
	if (cname_rrs->count != 1) {
		data->handler->error = true;
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_CNAME_MULTIPLE, NULL);
	}

	return KNOT_EOK;
}

static int check_dname(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *dname_rrs = node_rdataset(node, KNOT_RRTYPE_DNAME);
	if (dname_rrs == NULL) {
		return KNOT_EOK;
	}

	/* RFC 6672 Section 2.3 Paragraph 3 */
	bool is_apex = (node->flags & NODE_FLAGS_APEX);
	if (!is_apex && node_rrtype_exists(node, KNOT_RRTYPE_NS)) {
		data->handler->error = true;
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_DNAME_EXTRA_NS, NULL);
	}
	/* RFC 6672 Section 2.4 Paragraph 1 */
	/* If the NSEC3 node of the apex is present, it is counted as apex's child. */
	unsigned allowed_children = (is_apex && node_nsec3_get(node) != NULL) ? 1 : 0;
	if (node->children > allowed_children) {
		data->handler->error = true;
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_DNAME_CHILDREN, NULL);
	}
	/* RFC 6672 Section 2.4 Paragraph 2 */
	if (dname_rrs->count != 1) {
		data->handler->error = true;
		data->handler->cb(data->handler, data->zone, node->owner,
		                  SEM_ERR_DNAME_MULTIPLE, NULL);
	}

	return KNOT_EOK;
}

static int check_nsec3param(const zone_node_t *node, semchecks_data_t *data)
{
	if (data->zone->apex != node) {
		return KNOT_EOK;
	}

	const knot_rdataset_t *nsec3param_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC3PARAM);
	if (nsec3param_rrs == NULL) {
		return KNOT_EOK;
	}

	uint8_t param = knot_nsec3param_flags(nsec3param_rrs->rdata);
	if ((param & ~1) != 0) {
		data->handler->cb(data->handler, data->zone, data->zone->apex->owner,
		                  SEM_ERR_NSEC3PARAM_RDATA_FLAGS, NULL);
	}

	param = knot_nsec3param_alg(nsec3param_rrs->rdata);
	if (param != DNSSEC_NSEC3_ALGORITHM_SHA1) {
		data->handler->cb(data->handler, data->zone, data->zone->apex->owner,
		                  SEM_ERR_NSEC3PARAM_RDATA_ALG, NULL);
	}

	return KNOT_EOK;
}

static int do_checks_in_tree(zone_node_t *node, void *data)
{
	semchecks_data_t *s_data = (semchecks_data_t *)data;

	int ret = KNOT_EOK;

	for (int i = 0; ret == KNOT_EOK && i < CHECK_FUNCTIONS_LEN; ++i) {
		if (CHECK_FUNCTIONS[i].level & s_data->level) {
			ret = CHECK_FUNCTIONS[i].function(node, s_data);
			if (s_data->handler->fatal_error &&
			    (CHECK_FUNCTIONS[i].level & SOFT) &&
			    (s_data->level & SOFT)) {
				s_data->handler->fatal_error = false;
			}
		}
	}

	return ret;
}

static sem_error_t err_dnssec2sem(int ret, uint16_t rrtype, char *info, size_t len)
{
	char type_str[16];

	switch (ret) {
	case KNOT_DNSSEC_ENOSIG:
		if (knot_rrtype_to_string(rrtype, type_str, sizeof(type_str)) > 0) {
			(void)snprintf(info, len, "(record type %s)", type_str);
		}
		return SEM_ERR_RRSIG_UNVERIFIABLE;
	case KNOT_DNSSEC_ENONSEC:
		return SEM_ERR_NSEC_NONE;
	case KNOT_DNSSEC_ENSEC_BITMAP:
		return SEM_ERR_NSEC_RDATA_BITMAP;
	case KNOT_DNSSEC_ENSEC_CHAIN:
		return SEM_ERR_NSEC_RDATA_CHAIN;
	case KNOT_DNSSEC_ENSEC3_OPTOUT:
		return SEM_ERR_NSEC3_INSECURE_DELEGATION_OPT;
	default:
		return SEM_ERR_UNKNOWN;
	}
}

static int verify_dnssec(zone_contents_t *zone, sem_handler_t *handler, time_t time)
{
	zone_update_t fake_up = { .new_cont = zone, };
	int ret = knot_dnssec_validate_zone(&fake_up, NULL, time, false);
	if (fake_up.validation_hint.node != NULL) { // validation found an issue
		char info[64] = "";
		sem_error_t err = err_dnssec2sem(ret, fake_up.validation_hint.rrtype, info, sizeof(info));
		handler->cb(handler, zone, fake_up.validation_hint.node, err, info);
		return KNOT_EOK;
	} else if (ret == KNOT_INVALID_PUBLIC_KEY) { // validation failed due to invalid DNSKEY
		handler->cb(handler, zone, zone->apex->owner, SEM_ERR_DNSKEY_INVALID, NULL);
		return KNOT_EOK;
	} else { // validation failed by itself
		return ret;
	}
}

int sem_checks_process(zone_contents_t *zone, semcheck_optional_t optional, sem_handler_t *handler,
                       time_t time)
{
	if (handler == NULL) {
		return KNOT_EINVAL;
	}

	if (zone == NULL) {
		return KNOT_EEMPTYZONE;
	}

	semchecks_data_t data = {
		.handler = handler,
		.zone = zone,
		.level = MANDATORY,
		.time = time,
	};

	switch (optional) {
	case SEMCHECK_MANDATORY_SOFT:
		data.level |= SOFT;
		data.handler->soft_check = true;
		break;
	case SEMCHECK_DNSSEC_AUTO:
		data.level |= OPTIONAL;
		if (zone->dnssec) {
			data.level |= DNSSEC;
		}
		break;
	case SEMCHECK_DNSSEC_ON:
		data.level |= OPTIONAL;
		data.level |= DNSSEC;
		break;
	case SEMCHECK_DNSSEC_OFF:
		data.level |= OPTIONAL;
		break;
	default:
		break;
	}

	int ret = zone_contents_apply(zone, do_checks_in_tree, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}
	if (data.handler->fatal_error) {
		return KNOT_ESEMCHECK;
	}

	if (data.level & DNSSEC) {
		ret = verify_dnssec(zone, handler, time);
	}

	return ret;
}
