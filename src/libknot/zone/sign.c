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

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h> // TMP
#include <sys/types.h>
#include <time.h>

#include "common/hattrie/hat-trie.h"
#include "common/descriptor.h"
#include "common/errcode.h"
#include "sign.h"
#include "zone.h"
#include "node.h"
#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/sign/key.h"
#include "libknot/sign/dnssec.h"

#define MAX_RR_WIREFORMAT_SIZE (64 * 1024 * sizeof(uint8_t))
#define MAX_ZONE_KEYS 8

typedef struct {
	int count;
	knot_dnssec_key_t keys[MAX_ZONE_KEYS];
	knot_dnssec_sign_context_t *contexts[MAX_ZONE_KEYS];
	bool is_ksk[MAX_ZONE_KEYS];
} knot_zone_keys_t;

static knot_rrset_t *create_rrsig_rrset(knot_dname_t *owner,
					const knot_rrset_t *cover)
{
	return knot_rrset_new(owner, KNOT_RRTYPE_RRSIG, cover->rclass, cover->ttl);
}

// COPIED FROM SIG(0) AND MODIFIED
static size_t rrsig_rdata_size(const knot_dnssec_key_t *key)
{
	assert(key);

	size_t size;

	// static part

	size = sizeof(uint16_t)		// type covered
	     + sizeof(uint8_t)		// algorithm
	     + sizeof(uint8_t)		// labels
	     + sizeof(uint32_t)		// original TTL
	     + sizeof(uint32_t)		// signature expiration
	     + sizeof(uint32_t)		// signature inception
	     + sizeof(uint16_t);	// key tag (footprint)

	// variable part

	size += sizeof(knot_dname_t *); // pointer to signer
	size += knot_dnssec_sign_size(key);

	return size;
}

// COPIED FROM SIG(0) AND MODIFIED
static void rrsig_write_rdata(uint8_t *rdata,
                              const knot_dnssec_key_t *key,
                              const knot_dname_t *owner,
                              const knot_rrset_t *covered,
                              uint32_t sig_incepted,
                              uint32_t sig_expires)
{
	assert(key);
	assert(rdata);

	uint8_t *w = rdata;

	uint8_t owner_labels = knot_dname_label_count(owner);
	if (knot_dname_is_wildcard(owner))
		owner_labels -= 1;

	knot_wire_write_u16(w, covered->type);	// type covered
	w += sizeof(uint16_t);
	*w = key->algorithm;			// algorithm
	w += sizeof(uint8_t);
	*w = owner_labels;			// labels
	w += sizeof(uint8_t);
	knot_wire_write_u32(w, covered->ttl);	// original TTL
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_expires);	// signature expiration
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_incepted);	// signature inception
	w += sizeof(uint32_t);
	knot_wire_write_u16(w, key->keytag);	// key footprint
	w += sizeof(uint16_t);

	assert(w == rdata + 18);

	memcpy(w, &key->name, sizeof(knot_dname_t *)); // pointer to signer
	knot_dname_retain(key->name);
}

static uint8_t *create_rrsig_rdata(knot_rrset_t *rrsig, knot_dnssec_key_t *key)
{
	size_t rdata_size = rrsig_rdata_size(key);
	return knot_rrset_create_rdata(rrsig, rdata_size);
}

static int sign_rrset_one(knot_rrset_t *rrsig,
			  const knot_dname_t *owner,
			  const knot_rrset_t *covered,
			  knot_dnssec_key_t *key,
			  knot_dnssec_sign_context_t *sign_ctx)
{
	uint8_t *rdata = create_rrsig_rdata(rrsig, key);
	assert(rdata);

	// move to caller function, derive from key validity
	uint32_t sig_incept = (uint32_t)time(NULL); // 1369830271; //(uint32_t)time(NULL);
	uint32_t sig_expire = sig_incept + 2592000;

	rrsig_write_rdata(rdata, key, owner, covered, sig_incept, sig_expire);

	// RFC 4034
	// The signature coveres RRSIG RDATA field (excluding the signature)
	// and all matching RR records. All domain names are in cannonical
	// form.

	// new signature context (can be put at the end ... leave it here as it makes more sense in the flow)
	if (knot_dnssec_sign_new(sign_ctx) != KNOT_EOK) {
		fprintf(stderr, "dnssec sign new failed\n");
		return KNOT_ERROR;
	}

	knot_dnssec_sign_add(sign_ctx, rdata, 18); // static
	knot_dnssec_sign_add(sign_ctx, key->name->name, key->name->size);

	// huge blcok of rrsets can be optionally created
	uint8_t *rrwf = malloc(MAX_RR_WIREFORMAT_SIZE);
	if (!rrwf) {
		fprintf(stderr, "malloc failed\n");
		// free free free
		return KNOT_ENOMEM;
	}

	uint16_t rr_count = knot_rrset_rdata_rr_count(covered);
	for (uint16_t i = 0; i < rr_count; i++) {
		size_t rr_size;
		int result = knot_rrset_to_wire_one(covered, i, rrwf,
						    MAX_RR_WIREFORMAT_SIZE,
						    &rr_size, NULL);
		if (result != KNOT_EOK) {
			fprintf(stderr, "rrset_to_wire_one failed\n");
			// some free
			return KNOT_ENOMEM;
		}

		knot_dnssec_sign_add(sign_ctx, rrwf, rr_size);
	}

	int r = knot_dnssec_sign_write(sign_ctx, rdata + 18 + sizeof(knot_dname_t *));
	if (r != KNOT_EOK) {
		// some frees
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int sign_rrset(knot_dname_t *owner, const knot_rrset_t *covered,
                      knot_zone_keys_t *zone_keys, knot_rrset_t **out_rrsig)
{
	assert(owner);
	assert(covered);
	assert(zone_keys);
	assert(out_rrsig);

	char typestr[10] = "";
	knot_rrtype_to_string(covered->type, typestr, 10);
	fprintf(stderr, "signing rrset %s (%s)\n", knot_dname_to_str(owner), typestr);

	knot_rrset_t *rrsig = create_rrsig_rrset(owner, covered);
	assert(rrsig);

	bool use_ksk = covered->type == KNOT_RRTYPE_DNSKEY;

	for (int i = 0; i < zone_keys->count; i++) {
		if (zone_keys->is_ksk[i] && !use_ksk)
			continue;

		knot_dnssec_key_t *key = &zone_keys->keys[i];
		knot_dnssec_sign_context_t *ctx = zone_keys->contexts[i];

		fprintf(stderr, "signing with key %d (%s)\n",  key->keytag, zone_keys->is_ksk[i] ? "KSK" : "ZSK");

		int r = sign_rrset_one(rrsig, owner, covered, key, ctx);
		if (r != KNOT_EOK) {
			fprintf(stderr, "sign_rrset_one() failed %d\n", r);
			return r;
		}
	}

	*out_rrsig = rrsig;

	return KNOT_EOK;
}

static int sign_node(const knot_node_t *node, knot_zone_keys_t *zone_keys)
{
	assert(node);

	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t *rrset = node->rrset_tree[i];
		knot_rrset_t *sig_rrset = NULL;

		int r = sign_rrset(node->owner, rrset, zone_keys, &sig_rrset);
		if (r != KNOT_EOK) {
			fprintf(stderr, "sign_rrset() failed\n");
			return r;
		}
		if (!sig_rrset) {
			fprintf(stderr, "got empty RRSIG\n");
			continue;
		}

		knot_rrset_add_rrsigs(rrset, sig_rrset, KNOT_RRSET_DUPL_REPLACE);
	}

	return KNOT_EOK;
}

static int load_zone_keys(const char *keydir_name, knot_zone_keys_t *keys)
{
	assert(keydir_name);
	assert(keys);

	DIR *keydir = opendir(keydir_name);
	if (!keydir)
		return KNOT_DNSSEC_EINVALID_KEY;

	struct dirent entry_buf = { 0 };
	struct dirent *entry = NULL;
	while (keys->count < MAX_ZONE_KEYS && readdir_r(keydir, &entry_buf, &entry) == 0 && entry != NULL) {
		if (entry->d_name[0] != 'K')
			continue;

		char *suffix = strrchr(entry->d_name, '.');
		if (!suffix)
			continue;

		if (strcmp(suffix, ".private") != 0)
			continue;

		size_t path_len = strlen(keydir_name) + 1
		                + strlen(entry->d_name) + 1;
		char *path = malloc(path_len * sizeof(char));
		assert(path);
		snprintf(path, path_len, "%s/%s", keydir_name, entry->d_name);
		fprintf(stderr, "loading key '%s'\n", path);

		knot_key_params_t params = { 0 };
		int result = knot_load_key_params(path, &params);
		free(path);

		if (result != KNOT_EOK) {
			fprintf(stderr, "failed to load key params\n");
			continue;
		}

		assert(knot_get_key_type(&params) == KNOT_KEY_DNSSEC);

		result = knot_dnssec_key_from_params(&params, &keys->keys[keys->count]);
		if (result != KNOT_EOK) {
			fprintf(stderr, "cannot create the dnssec key\n");
			continue;
		}

		keys->is_ksk[keys->count] = params.flags & 1;

		keys->count += 1;
	}

	closedir(keydir);

	return KNOT_EOK;
}

static void free_sign_contexts(knot_zone_keys_t *keys)
{
	for (int i = 0; i < keys->count; i++) {
		knot_dnssec_sign_free(keys->contexts[i]);
		keys->contexts[i] = NULL;
	}
}

static int init_sign_contexts(knot_zone_keys_t *keys)
{
	assert(keys);

	for (int i = 0; i < keys->count; i++) {
		keys->contexts[i] = knot_dnssec_sign_init(&keys->keys[i]);
		if (keys->contexts[i] == NULL) {
			free_sign_contexts(keys);
			return KNOT_ENOMEM;
		}
	}

	return KNOT_EOK;
}

int knot_zone_sign(const knot_zone_t *zone, const char *keydir)
{
	assert(zone);
	assert(keydir);

	int result;

	knot_zone_keys_t zone_keys;
	memset(&zone_keys, '\0', sizeof(zone_keys));

	result = load_zone_keys(keydir, &zone_keys);
	if (result != KNOT_EOK) {
		fprintf(stderr, "load_zone_keys() failed\n");
		return result;
	}

	result = init_sign_contexts(&zone_keys);
	if (result != KNOT_EOK) {
		fprintf(stderr, "init_sign_contexts() failed\n");
		return result;
	}

	if (zone_keys.count == 0) {
		fprintf(stderr, "no zone keys available\n");
		return KNOT_EOK;
	}

	knot_zone_tree_t *tree = knot_zone_contents_get_nodes(zone->contents);
	bool sorted = false;

	hattrie_iter_t *it = hattrie_iter_begin(tree, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);
		sign_node(node, &zone_keys);
		hattrie_iter_next(it);
	}

	free_sign_contexts(&zone_keys);
	return KNOT_EOK;
}
