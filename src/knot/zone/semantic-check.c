/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libdnssec/error.h"
#include "contrib/base32hex.h"
#include "contrib/string.h"
#include "libknot/libknot.h"
#include "knot/zone/semantic-check.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-nsec.h"

static const char *error_messages[SEM_ERR_UNKNOWN + 1] = {
	[SEM_ERR_SOA_NONE] =
	"missing SOA at the zone apex",

	[SEM_ERR_CNAME_EXTRA_RECORDS] =
	"more records exist at CNAME",
	[SEM_ERR_CNAME_MULTIPLE] =
	"multiple CNAME records",

	[SEM_ERR_DNAME_CHILDREN] =
	"child record exists under DNAME",
	[SEM_ERR_DNAME_MULTIPLE] =
	"multiple DNAME records",
	[SEM_ERR_DNAME_EXTRA_NS] =
	"NS record exists at DNAME",

	[SEM_ERR_NS_APEX] =
	"missing NS at the zone apex",
	[SEM_ERR_NS_GLUE] =
	"missing glue record",

	[SEM_ERR_RRSIG_RDATA_TYPE_COVERED] =
	"wrong type covered in RRSIG",
	[SEM_ERR_RRSIG_RDATA_TTL] =
	"wrong original TTL in RRSIG",
	[SEM_ERR_RRSIG_RDATA_EXPIRATION] =
	"expired RRSIG",
	[SEM_ERR_RRSIG_RDATA_INCEPTION] =
	"RRSIG inception in the future",
	[SEM_ERR_RRSIG_RDATA_LABELS] =
	"wrong labels in RRSIG",
	[SEM_ERR_RRSIG_RDATA_OWNER] =
	"wrong signer's name in RRSIG",
	[SEM_ERR_RRSIG_NO_RRSIG] =
	"missing RRSIG",
	[SEM_ERR_RRSIG_SIGNED] =
	"signed RRSIG",
	[SEM_ERR_RRSIG_UNVERIFIABLE] =
	"unverifiable signature",

	[SEM_ERR_NSEC_NONE] =
	"missing NSEC",
	[SEM_ERR_NSEC_RDATA_BITMAP] =
	"incorrect type bitmap in NSEC",
	[SEM_ERR_NSEC_RDATA_MULTIPLE] =
	"multiple NSEC records",
	[SEM_ERR_NSEC_RDATA_CHAIN] =
	"incoherent NSEC chain",

	[SEM_ERR_NSEC3_NONE] =
	"missing NSEC3",
	[SEM_ERR_NSEC3_INSECURE_DELEGATION_OPT] =
	"insecure delegation outside NSEC3 opt-out",
	[SEM_ERR_NSEC3_EXTRA_RECORD] =
	"invalid record type in NSEC3 chain",
	[SEM_ERR_NSEC3_RDATA_TTL] =
	"inconsistent TTL for NSEC3 and minimum TTL in SOA",
	[SEM_ERR_NSEC3_RDATA_CHAIN] =
	"incoherent NSEC3 chain",
	[SEM_ERR_NSEC3_RDATA_BITMAP] =
	"incorrect type bitmap in NSEC3",
	[SEM_ERR_NSEC3_RDATA_FLAGS] =
	"incorrect flags in NSEC3",
	[SEM_ERR_NSEC3_RDATA_SALT] =
	"incorrect salt in NSEC3",
	[SEM_ERR_NSEC3_RDATA_ALG] =
	"incorrect algorithm in NSEC3",
	[SEM_ERR_NSEC3_RDATA_ITERS] =
	"incorrect number of iterations in NSEC3",

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
	[SEM_ERR_DNSKEY_RDATA_PROTOCOL] =
	"invalid protocol in DNSKEY",

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
	OPTIONAL =  1 << 1,
	NSEC =      1 << 2,
	NSEC3 =     1 << 3,
} check_level_t;

typedef struct {
	zone_contents_t *zone;
	sem_handler_t *handler;
	const zone_node_t *next_nsec;
	check_level_t level;
	time_t time;
} semchecks_data_t;

static int check_cname(const zone_node_t *node, semchecks_data_t *data);
static int check_dname(const zone_node_t *node, semchecks_data_t *data);
static int check_delegation(const zone_node_t *node, semchecks_data_t *data);
static int check_submission(const zone_node_t *node, semchecks_data_t *data);
static int check_ds(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data);
static int check_rrsig(const zone_node_t *node, semchecks_data_t *data);
static int check_rrsig_signed(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3_presence(const zone_node_t *node, semchecks_data_t *data);

struct check_function {
	int (*function)(const zone_node_t *, semchecks_data_t *);
	check_level_t level;
};

/* List of function callbacks for defined check_level */
static const struct check_function CHECK_FUNCTIONS[] = {
	{ check_cname,          MANDATORY },
	{ check_dname,          MANDATORY },
	{ check_delegation,     OPTIONAL },
	{ check_submission,     OPTIONAL },
	{ check_ds,             OPTIONAL },
	{ check_rrsig,          NSEC | NSEC3 },
	{ check_rrsig_signed,   NSEC | NSEC3 },
	{ check_nsec_bitmap,    NSEC | NSEC3 },
	{ check_nsec,           NSEC },
	{ check_nsec3,          NSEC3 },
	{ check_nsec3_presence, NSEC3 },
	{ check_nsec3_opt_out,  NSEC3 },
};

static const int CHECK_FUNCTIONS_LEN = sizeof(CHECK_FUNCTIONS)
                                     / sizeof(struct check_function);

static int dnssec_key_from_rdata(dnssec_key_t **key, const knot_dname_t *owner,
				 const uint8_t *rdata, size_t rdlen)
{
	if (!key || !rdata || rdlen == 0) {
		return KNOT_EINVAL;
	}

	const dnssec_binary_t binary_key = {
		.size = rdlen,
		.data = (uint8_t *)rdata
	};

	dnssec_key_t *new_key = NULL;
	int ret = dnssec_key_new(&new_key);
	if (ret != DNSSEC_EOK) {
		return KNOT_ENOMEM;
	}
	ret = dnssec_key_set_rdata(new_key, &binary_key);
	if (ret != DNSSEC_EOK) {
		dnssec_key_free(new_key);
		return KNOT_ENOMEM;
	}
	if (owner) {
		ret = dnssec_key_set_dname(new_key, owner);
		if (ret != DNSSEC_EOK) {
			dnssec_key_free(new_key);
			return KNOT_ENOMEM;
		}
	}

	*key = new_key;
	return KNOT_EOK;
}

static int check_signature(const knot_rdata_t *rrsig, const dnssec_key_t *key,
                           const knot_rrset_t *covered)
{
	if (!rrsig || !key || !dnssec_key_can_verify(key)) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	dnssec_sign_ctx_t *sign_ctx = NULL;

	dnssec_binary_t signature = {
		.size = knot_rrsig_signature_len(rrsig),
		.data = (uint8_t *)knot_rrsig_signature(rrsig)
	};
	if (!signature.data || !signature.size) {
		ret = KNOT_EINVAL;
		goto fail;
	}

	if (dnssec_sign_new(&sign_ctx, key) != KNOT_EOK) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	if (knot_sign_ctx_add_data(sign_ctx, rrsig->data, covered) != KNOT_EOK) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	if (dnssec_sign_verify(sign_ctx, &signature) != KNOT_EOK) {
		ret = KNOT_EINVAL;
		goto fail;
	}

fail:
	dnssec_sign_free(sign_ctx);
	return ret;
}

/*!
 * \brief Semantic check - RRSIG rdata.
 *
 * \param handler    Pointer on function to be called in case of negative check.
 * \param zone       The zone the rrset is in.
 * \param node       The node in the zone contents.
 * \param rrsig      RRSIG rdata.
 * \param rrset      RRSet signed by the RRSIG.
 * \param context    The time stamp we check the rrsig validity according to.
 * \param level      Level of the check.
 * \param verified   Out: the RRSIG has been verified to be signed by existing DNSKEY.
 *
 * \retval KNOT_EOK on success.
 * \return Appropriate error code if error was found.
 */
static int check_rrsig_rdata(sem_handler_t *handler,
                             const zone_contents_t *zone,
                             const zone_node_t *node,
                             const knot_rdata_t *rrsig,
                             const knot_rrset_t *rrset,
                             time_t context,
                             check_level_t level,
                             bool *verified)
{
	/* Prepare additional info string. */
	char info_str[50] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rrset->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "(record type %s)", type_str);
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}

	if (knot_rrsig_type_covered(rrsig) != rrset->type) {
		handler->cb(handler, zone, node, SEM_ERR_RRSIG_RDATA_TYPE_COVERED,
		            info_str);
	}

	/* label number at the 2nd index should be same as owner's */
	uint8_t labels_rdata = knot_rrsig_labels(rrsig);

	size_t tmp = knot_dname_labels(rrset->owner, NULL) - labels_rdata;
	if (tmp != 0) {
		/* if name has wildcard, label must not be included */
		if (!knot_dname_is_wildcard(rrset->owner)) {
			handler->cb(handler, zone, node, SEM_ERR_RRSIG_RDATA_LABELS,
			            info_str);
		} else if (tmp != 1) {
			handler->cb(handler, zone, node, SEM_ERR_RRSIG_RDATA_LABELS,
			            info_str);
		}
	}

	/* Check original TTL. */
	uint32_t original_ttl = knot_rrsig_original_ttl(rrsig);
	if (original_ttl != rrset->ttl) {
		handler->cb(handler, zone, node, SEM_ERR_RRSIG_RDATA_TTL,
		            info_str);
	}

	/* Check for expired signature. */
	if (knot_rrsig_sig_expiration(rrsig) < context) {
		handler->cb(handler, zone, node, SEM_ERR_RRSIG_RDATA_EXPIRATION,
		            info_str);
	}

	/* Check inception */
	if (knot_rrsig_sig_inception(rrsig) > context) {
		handler->cb(handler, zone, node, SEM_ERR_RRSIG_RDATA_INCEPTION,
		            info_str);
	}

	/* Check signer name. */
	const knot_dname_t *signer = knot_rrsig_signer_name(rrsig);
	if (!knot_dname_is_equal(signer, zone->apex->owner)) {
		handler->cb(handler, zone, node, SEM_ERR_RRSIG_RDATA_OWNER,
		            info_str);
	}

	/* Verify with public key - only one RRSIG of covered record needed */
	if (level & OPTIONAL && !*verified) {
		const knot_rdataset_t *dnskeys = node_rdataset(zone->apex, KNOT_RRTYPE_DNSKEY);
		if (dnskeys == NULL) {
			return KNOT_EOK;
		}

		for (int i = 0; i < dnskeys->count; i++) {
			knot_rdata_t *dnskey = knot_rdataset_at(dnskeys, i);
			uint16_t flags = knot_dnskey_flags(dnskey);
			uint8_t proto = knot_dnskey_proto(dnskey);
			/* RFC 4034 2.1.1 & 2.1.2 */
			if (flags & DNSKEY_FLAGS_ZSK && proto == 3) {
				dnssec_key_t *key;

				ret = dnssec_key_from_rdata(&key, zone->apex->owner,
				                            dnskey->data, dnskey->len);
				if (ret != KNOT_EOK) {
					continue;
				}

				ret = check_signature(rrsig, key, rrset);
				dnssec_key_free(key);
				if (ret == KNOT_EOK) {
					*verified = true;
					break;
				}
			}
		}
	}

	return KNOT_EOK;
}

static int check_rrsig_signed(const zone_node_t *node, semchecks_data_t *data)
{
	/* signed rrsig - nonsense */
	if (node_rrtype_is_signed(node, KNOT_RRTYPE_RRSIG)) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_RRSIG_SIGNED, NULL);
	}

	return KNOT_EOK;
}
/*!
 * \brief Semantic check - RRSet's RRSIG.
 *
 * \param handler    Pointer on function to be called in case of negative check.
 * \param zone       The zone the rrset is in.
 * \param node       The node in the zone contents.
 * \param rrset      RRSet signed by the RRSIG.
 * \param context    The time stamp we check the rrsig validity according to.
 * \param level      Level of the check.
 *
 * \retval KNOT_EOK on success.
 * \return Appropriate error code if error was found.
 */
static int check_rrsig_in_rrset(sem_handler_t *handler,
                                const zone_contents_t *zone,
                                const zone_node_t *node,
                                const knot_rrset_t *rrset,
                                time_t context,
                                check_level_t level)
{
	if (handler == NULL || node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}
	/* Prepare additional info string. */
	char info_str[50] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rrset->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "(record type %s)", type_str);
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}

	knot_rrset_t node_rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);

	knot_rdataset_t rrsigs;
	knot_rdataset_init(&rrsigs);
	ret = knot_synth_rrsig(rrset->type, &node_rrsigs.rrs, &rrsigs, NULL);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return ret;
	}
	if (ret == KNOT_ENOENT) {
		handler->cb(handler, zone, node, SEM_ERR_RRSIG_NO_RRSIG, info_str);
		return KNOT_EOK;
	}

	bool verified = false;
	knot_rdata_t *rrsig = rrsigs.rdata;
	for (uint16_t i = 0; ret == KNOT_EOK && i < rrsigs.count; ++i) {
		ret = check_rrsig_rdata(handler, zone, node, rrsig, rrset,
		                        context, level, &verified);
		rrsig = knot_rdataset_next(rrsig);
	}
	/* Only one rrsig of covered record needs to be verified by DNSKEY. */
	if (!verified) {
		handler->cb(handler, zone, node, SEM_ERR_RRSIG_UNVERIFIABLE,
		            info_str);
	}

	knot_rdataset_clear(&rrsigs, NULL);
	return KNOT_EOK;;
}

/*!
 * \brief Check if glue record for delegation is present.
 *
 * Also check if there is NS record in the zone.
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_delegation(const zone_node_t *node, semchecks_data_t *data)
{
	if (!((node->flags & NODE_FLAGS_DELEG) || data->zone->apex == node)) {
		return KNOT_EOK;
	}

	const knot_rdataset_t *ns_rrs = node_rdataset(node, KNOT_RRTYPE_NS);
	if (ns_rrs == NULL) {
		assert(data->zone->apex == node);
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NS_APEX, NULL);
		return KNOT_EOK;
	}

	// check glue record for delegation
	for (int i = 0; i < ns_rrs->count; ++i) {
		knot_rdata_t *ns_rr = knot_rdataset_at(ns_rrs, i);
		const knot_dname_t *ns_dname = knot_ns_name(ns_rr);
		if (knot_dname_in_bailiwick(ns_dname, node->owner) <= 0) {
			continue;
		}

		const zone_node_t *glue_node =
			zone_contents_find_node(data->zone, ns_dname);

		if (glue_node == NULL) {
			/* Try wildcard ([1]* + suffix). */
			knot_dname_t wildcard[KNOT_DNAME_MAXLEN];
			memcpy(wildcard, "\x1""*", 2);
			knot_dname_to_wire(wildcard + 2,
			                   knot_wire_next_label(ns_dname, NULL),
			                   sizeof(wildcard) - 2);
			glue_node = zone_contents_find_node(data->zone, wildcard);
		}
		if (!node_rrtype_exists(glue_node, KNOT_RRTYPE_A) &&
		    !node_rrtype_exists(glue_node, KNOT_RRTYPE_AAAA)) {
			data->handler->cb(data->handler, data->zone, node,
			                  SEM_ERR_NS_GLUE, NULL);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief check_submission_records Check CDS and CDNSKEY
 */
static int check_submission(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *cdss = node_rdataset(node, KNOT_RRTYPE_CDS);
	const knot_rdataset_t *cdnskeys = node_rdataset(node, KNOT_RRTYPE_CDNSKEY);
	if (cdss == NULL && cdnskeys == NULL) {
		return KNOT_EOK;
	} else if (cdss == NULL) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_CDS_NONE, NULL);
		return KNOT_EOK;
	} else if (cdnskeys == NULL) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_CDNSKEY_NONE, NULL);
		return KNOT_EOK;
	}

	const knot_rdataset_t *dnskeys = node_rdataset(data->zone->apex,
	                                               KNOT_RRTYPE_DNSKEY);
	if (dnskeys == NULL) {
		data->handler->cb(data->handler, data->zone, node,
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
		for (int j = 0; j < dnskeys->count; j++) {
			knot_rdata_t *dnskey = knot_rdataset_at(dnskeys, j);

			if (knot_rdata_cmp(dnskey, cdnskey) == 0) {
				match = true;
				break;
			}
		}
		if (!match) {
			data->handler->cb(data->handler, data->zone, node,
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
			data->handler->cb(data->handler, data->zone, node,
			                  SEM_ERR_CDS_NOT_MATCH, NULL);
		}
	}

	// check delete-dnssec records
	if ((delete_cds && (!delete_cdnskey || cdss->count > 1)) ||
	    (delete_cdnskey && (!delete_cds || cdnskeys->count > 1))) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_CDNSKEY_INVALID_DELETE, NULL);
	}

	// check orphaned CDS
	if (cdss->count < cdnskeys->count) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_CDNSKEY_NO_CDS, NULL);
	}

	return KNOT_EOK;
}

/*!
 * \brief Semantic check - DS record.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 *
 * \retval KNOT_EOK on success.
 * \return Appropriate error code if error was found.
 */
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

		char info[100] = "";
		(void)snprintf(info, sizeof(info), "(keytag %d)", keytag);

		if (!dnssec_algorithm_digest_support(digest_type)) {
			data->handler->cb(data->handler, data->zone, node,
			                  SEM_ERR_DS_RDATA_ALG, info);
		} else {
			// Sizes for different digest algorithms.
			const uint16_t digest_sizes [] = { 0, 20, 32, 32, 48};

			uint16_t digest_size = knot_ds_digest_len(ds);

			if (digest_sizes[digest_type] != digest_size) {
				data->handler->cb(data->handler, data->zone, node,
				                  SEM_ERR_DS_RDATA_DIGLEN, info);
			}
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Run all semantic check related to RRSIG record
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_rrsig(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	bool deleg = node->flags & NODE_FLAGS_DELEG;

	int ret = KNOT_EOK;

	int rrset_count = node->rrset_count;
	for (int i = 0; ret == KNOT_EOK && i < rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		if (deleg && rrset.type != KNOT_RRTYPE_NSEC &&
		    rrset.type != KNOT_RRTYPE_DS ) {
			continue;
		}

		ret = check_rrsig_in_rrset(data->handler, data->zone, node, &rrset,
		                           data->time, data->level);
	}
	return ret;
}

/*!
 * \brief Add all RR types from a node into the bitmap.
 */
static void bitmap_add_all_node_rrsets(dnssec_nsec_bitmap_t *bitmap,
                                       const zone_node_t *node)
{
	bool deleg = node->flags & NODE_FLAGS_DELEG;
	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rr = node_rrset_at(node, i);
		if (deleg && (rr.type != KNOT_RRTYPE_NS &&
		              rr.type != KNOT_RRTYPE_DS &&
		              rr.type != KNOT_RRTYPE_NSEC &&
		              rr.type != KNOT_RRTYPE_RRSIG)) {
			continue;
		}
		dnssec_nsec_bitmap_add(bitmap, rr.type);
	}
}

static char *nsec3_info(const knot_dname_t *owner, char *out, size_t out_len)
{
	char buff[KNOT_DNAME_TXT_MAXLEN + 1];
	char *str = knot_dname_to_str(buff, owner, sizeof(buff));
	if (str == NULL) {
		return NULL;
	}

	int ret = snprintf(out, out_len, "(NSEC3 owner=%s)", str);
	if (ret <= 0 || ret >= out_len) {
		return NULL;
	}

	return out;
}

/*!
 * \brief Check NSEC and NSEC3 type bitmap
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	bool nsec = data->level & NSEC;
	knot_rdataset_t *nsec_rrs = NULL;

	if (nsec) {
		nsec_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC);
	} else if (node->nsec3_node != NULL) {
		nsec_rrs = node_rdataset(node->nsec3_node, KNOT_RRTYPE_NSEC3);
	}
	if (nsec_rrs == NULL) {
		return KNOT_EOK;
	}

	// create NSEC bitmap from node
	dnssec_nsec_bitmap_t *node_bitmap = dnssec_nsec_bitmap_new();
	if (node_bitmap == NULL) {
		return KNOT_ENOMEM;
	}
	bitmap_add_all_node_rrsets(node_bitmap, node);

	uint16_t node_wire_size = dnssec_nsec_bitmap_size(node_bitmap);
	uint8_t *node_wire = malloc(node_wire_size);
	if (node_wire == NULL) {
		dnssec_nsec_bitmap_free(node_bitmap);
		return KNOT_ENOMEM;
	}
	dnssec_nsec_bitmap_write(node_bitmap, node_wire);
	dnssec_nsec_bitmap_free(node_bitmap);

	// get NSEC bitmap from NSEC node
	const uint8_t *nsec_wire = NULL;
	uint16_t nsec_wire_size = 0;
	if (nsec) {
		nsec_wire = knot_nsec_bitmap(nsec_rrs->rdata);
		nsec_wire_size = knot_nsec_bitmap_len(nsec_rrs->rdata);
	} else {
		nsec_wire = knot_nsec3_bitmap(nsec_rrs->rdata);
		nsec_wire_size = knot_nsec3_bitmap_len(nsec_rrs->rdata);
	}

	if (node_wire_size != nsec_wire_size ||
	    memcmp(node_wire, nsec_wire, node_wire_size) != 0) {
		char buff[50 + KNOT_DNAME_TXT_MAXLEN];
		char *info = nsec ? NULL : nsec3_info(node->nsec3_node->owner,
		                                      buff, sizeof(buff));
		data->handler->cb(data->handler, data->zone, node,
		                  (nsec ? SEM_ERR_NSEC_RDATA_BITMAP : SEM_ERR_NSEC3_RDATA_BITMAP),
		                  info);
	}

	free(node_wire);
	return KNOT_EOK;
}

/*!
 * \brief Run NSEC related semantic checks
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	if (node->rrset_count == 0) { // empty nonterminal
		return KNOT_EOK;
	}

	/* check for NSEC record */
	const knot_rdataset_t *nsec_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC);
	if (nsec_rrs == NULL) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC_NONE, NULL);
		return KNOT_EOK;
	}

	/* Test that only one record is in the NSEC RRSet */
	if (nsec_rrs->count != 1) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC_RDATA_MULTIPLE, NULL);
	}

	if (data->next_nsec != node) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC_RDATA_CHAIN, NULL);
	}

	/*
	 * Test that NSEC chain is coherent.
	 * We have already checked that every
	 * authoritative node contains NSEC record
	 * so checking should only be matter of testing
	 * the next link in each node.
	 */
	const knot_dname_t *next_domain = knot_nsec_next(nsec_rrs->rdata);

	data->next_nsec = zone_contents_find_node(data->zone, next_domain);
	if (data->next_nsec == NULL) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC_RDATA_CHAIN, NULL);
	}

	return KNOT_EOK;
}

/*!
 * \brief Check if node has NSEC3 node.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3_presence(const zone_node_t *node, semchecks_data_t *data)
{
	bool auth = (node->flags & NODE_FLAGS_NONAUTH) == 0;
	bool deleg = (node->flags & NODE_FLAGS_DELEG) != 0;

	if ((deleg && node_rrtype_exists(node, KNOT_RRTYPE_DS)) || (auth && !deleg)) {
		if (node->nsec3_node == NULL) {
			data->handler->cb(data->handler, data->zone, node,
			                  SEM_ERR_NSEC3_NONE, NULL);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Check NSEC3 opt-out.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data)
{
	if (!(node->nsec3_node == NULL && node->flags & NODE_FLAGS_DELEG)) {
		return KNOT_EOK;
	}
	/* Insecure delegation, check whether it is part of opt-out span. */

	const zone_node_t *nsec3_previous = NULL;
	const zone_node_t *nsec3_node;
	zone_contents_find_nsec3_for_name(data->zone, node->owner, &nsec3_node,
	                                  &nsec3_previous);

	if (nsec3_previous == NULL) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_NONE, NULL);
		return KNOT_EOK;
	}

	const knot_rdataset_t *previous_rrs;
	previous_rrs = node_rdataset(nsec3_previous, KNOT_RRTYPE_NSEC3);
	assert(previous_rrs);

	/* Check for opt-out flag. */
	uint8_t flags = knot_nsec3_flags(previous_rrs->rdata);
	if (!(flags & 1)) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_INSECURE_DELEGATION_OPT, NULL);
	}

	return KNOT_EOK;
}

/*!
 * \brief Run checks related to NSEC3.
 *
 * Check NSEC3 node for given node.
 * Check if NSEC3 chain is coherent and cyclic.
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	bool auth = (node->flags & NODE_FLAGS_NONAUTH) == 0;
	bool deleg = (node->flags & NODE_FLAGS_DELEG) != 0;

	if (!auth && !deleg) {
		return KNOT_EOK;
	}
	if (node->nsec3_node == NULL) {
		return KNOT_EOK;
	}

	dnssec_nsec3_params_t params_apex = { 0 };
	int ret = KNOT_EOK;

	char buff[50 + KNOT_DNAME_TXT_MAXLEN];
	char *info = nsec3_info(node->nsec3_node->owner, buff, sizeof(buff));

	knot_rrset_t nsec3_rrs = node_rrset(node->nsec3_node, KNOT_RRTYPE_NSEC3);
	if (knot_rrset_empty(&nsec3_rrs)) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_NONE, info);
		goto nsec3_cleanup;
	}

	const knot_rdataset_t *soa_rrs = node_rdataset(data->zone->apex, KNOT_RRTYPE_SOA);
	assert(soa_rrs);
	uint32_t minimum_ttl = knot_soa_minimum(soa_rrs->rdata);
	if (nsec3_rrs.ttl != minimum_ttl) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_RDATA_TTL, info);
	}

	// Check parameters.
	const knot_rdataset_t *nsec3param = node_rdataset(data->zone->apex,
	                                                  KNOT_RRTYPE_NSEC3PARAM);
	dnssec_binary_t rdata = {
		.size = nsec3param->rdata->len,
		.data = nsec3param->rdata->data
	};
	ret = dnssec_nsec3_params_from_rdata(&params_apex, &rdata);
	if (ret != DNSSEC_EOK) {
		ret = knot_error_from_libdnssec(ret);
		goto nsec3_cleanup;
	}

	if (knot_nsec3_flags(nsec3_rrs.rrs.rdata) > 1) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_RDATA_FLAGS, info);
	}

	dnssec_binary_t salt = {
		.size = knot_nsec3_salt_len(nsec3_rrs.rrs.rdata),
		.data = (uint8_t *)knot_nsec3_salt(nsec3_rrs.rrs.rdata),
	};

	if (dnssec_binary_cmp(&salt, &params_apex.salt)) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_RDATA_SALT, info);
	}

	if (knot_nsec3_alg(nsec3_rrs.rrs.rdata) != params_apex.algorithm) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_RDATA_ALG, info);
	}

	if (knot_nsec3_iters(nsec3_rrs.rrs.rdata) != params_apex.iterations) {
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_RDATA_ITERS, info);
	}

	// Get next nsec3 node.
	const zone_node_t *apex = data->zone->apex;
	const uint8_t *next_dname_str = knot_nsec3_next(nsec3_rrs.rrs.rdata);
	uint8_t next_dname_str_size = knot_nsec3_next_len(nsec3_rrs.rrs.rdata);
	uint8_t next_dname[KNOT_DNAME_MAXLEN];
	ret = knot_nsec3_hash_to_dname(next_dname, sizeof(next_dname),
	                               next_dname_str, next_dname_str_size,
	                               apex->owner);
	if (ret != KNOT_EOK) {
		goto nsec3_cleanup;
	}

	const zone_node_t *next_nsec3 = zone_contents_find_nsec3_node(data->zone,
	                                                              next_dname);
	if (next_nsec3 == NULL || next_nsec3->prev != node->nsec3_node) {
		uint8_t *next = NULL;
		int32_t next_len = base32hex_encode_alloc(next_dname_str,
		                                          next_dname_str_size,
		                                          &next);
		char *hash_info = NULL;
		if (next != NULL) {
			hash_info = sprintf_alloc("(next hash %.*s)", next_len, next);
			free(next);
		}
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_NSEC3_RDATA_CHAIN, hash_info);
		free(hash_info);
	}

	ret = check_rrsig(node->nsec3_node, data);
	if (ret != KNOT_EOK) {
		goto nsec3_cleanup;
	}

	// Check that the node only contains NSEC3 and RRSIG.
	for (int i = 0; ret == KNOT_EOK && i < node->nsec3_node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node->nsec3_node, i);
		uint16_t type = rrset.type;
		if (type != KNOT_RRTYPE_NSEC3 && type != KNOT_RRTYPE_RRSIG) {
			data->handler->cb(data->handler, data->zone, node->nsec3_node,
			                  SEM_ERR_NSEC3_EXTRA_RECORD, NULL);
		}
	}

nsec3_cleanup:
	dnssec_nsec3_params_free(&params_apex);

	return ret;
}

/*!
 * \brief Check if CNAME record contains other records
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
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
		data->handler->fatal_error = true;
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_CNAME_EXTRA_RECORDS, NULL);
	}
	if (cname_rrs->count != 1) {
		data->handler->fatal_error = true;
		data->handler->cb(data->handler, data->zone, node,
		                  SEM_ERR_CNAME_MULTIPLE, NULL);
	}

	return KNOT_EOK;
}

/*!
 * \brief Check if node with DNAME record satisfies RFC 6672 Section 2.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_dname(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *dname_rrs = node_rdataset(node, KNOT_RRTYPE_DNAME);
	if (dname_rrs != NULL) {
		/* RFC 6672 Section 2.3 Paragraph 3 */
		bool is_apex = (node->parent == NULL);
		if (!is_apex && node_rrtype_exists(node, KNOT_RRTYPE_NS)) {
			data->handler->fatal_error = true;
			data->handler->cb(data->handler, data->zone, node,
			                  SEM_ERR_DNAME_EXTRA_NS, NULL);
		}
		/* RFC 6672 Section 2.4 Paragraph 1 */
		/* If the NSEC3 node of the apex is present, it is counted as apex's child. */
		unsigned allowed_children = (is_apex && node->nsec3_node != NULL) ? 1 : 0;
		if (node->children > allowed_children) {
			data->handler->fatal_error = true;
			data->handler->cb(data->handler, data->zone, node,
			                  SEM_ERR_DNAME_CHILDREN, NULL);
		}
		/* RFC 6672 Section 2.4 Paragraph 2 */
		if (dname_rrs->count != 1) {
			data->handler->fatal_error = true;
			data->handler->cb(data->handler, data->zone, node,
			              SEM_ERR_DNAME_MULTIPLE, NULL);
		}
	}
	return KNOT_EOK;
}

/*!
 * \brief Check that NSEC chain is cyclic.
 *
 * Run only once per zone. Check that last NSEC node points to first one.
 * \param data Semantic checks context data
 */
static int check_nsec_cyclic(semchecks_data_t *data)
{
	if (data->next_nsec == NULL) {
		data->handler->cb(data->handler, data->zone, data->zone->apex,
		                  SEM_ERR_NSEC_RDATA_CHAIN, NULL);
		return KNOT_EOK;
	}
	if (!knot_dname_is_equal(data->next_nsec->owner, data->zone->apex->owner)) {
		data->handler->cb(data->handler, data->zone, data->next_nsec,
		                  SEM_ERR_NSEC_RDATA_CHAIN, NULL);
	}

	return KNOT_EOK;
}

/*!
 * \brief Call all semantic checks for each node.
 *
 * This function is called as callback from zone_contents_tree_apply_inorder.
 * Checks are functions from global const array check_functions.
 *
 * \param node Node to be checked
 * \param data Semantic checks context data
 */
static int do_checks_in_tree(zone_node_t *node, void *data)
{
	semchecks_data_t *s_data = (semchecks_data_t *)data;

	int ret = KNOT_EOK;

	for (int i = 0; ret == KNOT_EOK && i < CHECK_FUNCTIONS_LEN; ++i) {
		if (CHECK_FUNCTIONS[i].level & s_data->level) {
			ret = CHECK_FUNCTIONS[i].function(node, s_data);
		}
	}


	return ret;
}

static void check_nsec3param(knot_rdataset_t *nsec3param, zone_contents_t *zone,
                             sem_handler_t *handler, semchecks_data_t *data)
{
	assert(nsec3param);

	data->level |= NSEC3;
	uint8_t param = knot_nsec3param_flags(nsec3param->rdata);
	if ((param & ~1) != 0) {
		handler->cb(handler, zone, zone->apex, SEM_ERR_NSEC3PARAM_RDATA_FLAGS,
		            NULL);
	}

	param = knot_nsec3param_alg(nsec3param->rdata);
	if (param != DNSSEC_NSEC3_ALGORITHM_SHA1) {
		handler->cb(handler, zone, zone->apex, SEM_ERR_NSEC3PARAM_RDATA_ALG,
		            NULL);
	}
}

static void check_dnskey(zone_contents_t *zone, sem_handler_t *handler)
{
	const knot_rdataset_t *dnskeys = node_rdataset(zone->apex, KNOT_RRTYPE_DNSKEY);
	if (dnskeys == NULL) {
		handler->cb(handler, zone, zone->apex, SEM_ERR_DNSKEY_NONE, NULL);
		return;
	}

	for (int i = 0; i < dnskeys->count; i++) {
		knot_rdata_t *dnskey = knot_rdataset_at(dnskeys, i);
		dnssec_key_t *key;
		int ret = dnssec_key_from_rdata(&key, zone->apex->owner,
		                                dnskey->data, dnskey->len);
		if (ret == KNOT_EOK) {
			dnssec_key_free(key);
		} else {
			handler->cb(handler, zone, zone->apex, SEM_ERR_DNSKEY_INVALID, NULL);
		}

		if (knot_dnskey_proto(dnskey) != 3) {
			handler->cb(handler, zone, zone->apex, SEM_ERR_DNSKEY_RDATA_PROTOCOL,
			            NULL);
		}

		dnssec_key_algorithm_t alg = knot_dnskey_alg(dnskey);
		if (!dnssec_algorithm_key_support(alg)) {
			char *info = sprintf_alloc("(unsupported algorithm %d)", alg);
			handler->cb(handler, zone, zone->apex, SEM_ERR_DNSKEY_INVALID, info);
			free(info);
		}
	}
}

int sem_checks_process(zone_contents_t *zone, bool optional, sem_handler_t *handler,
                       time_t time)
{
	if (zone == NULL || handler == NULL) {
		return KNOT_EINVAL;
	}

	semchecks_data_t data = {
		.handler = handler,
		.zone = zone,
		.next_nsec = zone->apex,
		.level = MANDATORY,
		.time = time,
	};

	if (optional) {
		data.level |= OPTIONAL;
		if (zone->dnssec) {
			knot_rdataset_t *nsec3param = node_rdataset(zone->apex,
			                                            KNOT_RRTYPE_NSEC3PARAM);
			if (nsec3param != NULL) {
				data.level |= NSEC3;
				check_nsec3param(nsec3param, zone, handler, &data);
			} else {
				data.level |= NSEC;
			}
			check_dnskey(zone, handler);
		}
	}

	int ret = zone_contents_apply(zone, do_checks_in_tree, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}
	if (data.handler->fatal_error) {
		return KNOT_ESEMCHECK;
	}

	// check cyclic chain after every node was checked
	if (data.level & NSEC) {
		check_nsec_cyclic(&data);
	}
	if (data.handler->fatal_error) {
		return KNOT_ESEMCHECK;
	}

	return KNOT_EOK;
}
