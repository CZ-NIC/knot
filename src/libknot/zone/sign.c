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

#include "common/descriptor.h"
#include "common/errcode.h"
#include "common/hattrie/hat-trie.h"
#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/sign/dnssec.h"
#include "libknot/sign/key.h"
#include "node.h"
#include "sign.h"
#include "zone-contents.h"

#define MAX_RR_WIREFORMAT_SIZE (64 * 1024 * sizeof(uint8_t))
#define MAX_ZONE_KEYS 8

typedef struct {
	int count;
	knot_dnssec_key_t keys[MAX_ZONE_KEYS];
	knot_dnssec_sign_context_t *contexts[MAX_ZONE_KEYS];
	bool is_ksk[MAX_ZONE_KEYS];
} knot_zone_keys_t;

typedef struct {
	uint32_t sign_lifetime; //! Signature life time.
	uint32_t sign_refresh;  //! Signature refresh time before expiration.
} knot_dnssec_policy_t;

#define DEFAULT_DNSSEC_POLICY { .sign_lifetime = 2592000, .sign_refresh = 7200 }

static uint32_t time_now(void)
{
	return (uint32_t)time(NULL);
}

static knot_rrset_t *create_rrsig_rrset(const knot_rrset_t *cover)
{
	return knot_rrset_new(cover->owner, KNOT_RRTYPE_RRSIG, cover->rclass,
	                      cover->ttl);
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

static int sign_rrset_one(knot_rrset_t *rrsigs,
                          const knot_rrset_t *covered,
                          knot_dnssec_key_t *key,
                          knot_dnssec_sign_context_t *sign_ctx,
                          const knot_dnssec_policy_t *policy)
{
	uint8_t *rdata = create_rrsig_rdata(rrsigs, key);
	if (!rdata)
		return KNOT_ENOMEM;

	uint32_t sig_incept = time_now();
	uint32_t sig_expire = sig_incept + policy->sign_lifetime;

	rrsig_write_rdata(rdata, key, covered->owner, covered, sig_incept, sig_expire);

	// RFC 4034: The signature coveres RRSIG RDATA field (excluding the
	// signature) and all matching RR records, which are ordered
	// canonically.

	int result = knot_dnssec_sign_new(sign_ctx);
	if (result != KNOT_EOK)
		return result;

	knot_dnssec_sign_add(sign_ctx, rdata, 18); // static
	knot_dnssec_sign_add(sign_ctx, key->name->name, key->name->size);

	// huge block of rrsets can be optionally created
	uint8_t *rrwf = malloc(MAX_RR_WIREFORMAT_SIZE);
	if (!rrwf)
		return KNOT_ENOMEM;

	uint16_t rr_count = knot_rrset_rdata_rr_count(covered);
	for (uint16_t i = 0; i < rr_count; i++) {
		size_t rr_size;
		result = knot_rrset_to_wire_one(covered, i, rrwf,
		                                MAX_RR_WIREFORMAT_SIZE,
		                                &rr_size, NULL);
		if (result != KNOT_EOK) {
			free(rrwf);
			return result;
		}

		knot_dnssec_sign_add(sign_ctx, rrwf, rr_size);
	}

	uint8_t *rdata_signature = rdata + 18 + sizeof(knot_dname_t *);
	result = knot_dnssec_sign_write(sign_ctx, rdata_signature);

	free(rrwf);

	return result;
}

static bool signature_exists(const knot_rrset_t *rrsigs,
			     const knot_dnssec_key_t *key)
{
	for (int i = 0; i < rrsigs->rdata_count; i++) {
		uint16_t keytag = knot_rrset_rdata_rrsig_key_tag(rrsigs, i);
		if (keytag == key->keytag)
			return true;
	}

	return false;
}

static int add_missing_signatures(const knot_rrset_t *covered,
                                  knot_rrset_t *rrsigs,
                                  knot_zone_keys_t *zone_keys,
                                  const knot_dnssec_policy_t *policy)
{
	assert(covered);
	assert(rrsigs);
	assert(zone_keys);
	assert(policy);

	bool use_ksk = covered->type == KNOT_RRTYPE_DNSKEY;

	for (int i = 0; i < zone_keys->count; i++) {
		if (use_ksk != zone_keys->is_ksk[i])
			continue;

		knot_dnssec_key_t *key = &zone_keys->keys[i];
		knot_dnssec_sign_context_t *ctx = zone_keys->contexts[i];

		if (signature_exists(rrsigs, key))
			continue;

		int r = sign_rrset_one(rrsigs, covered, key, ctx, policy);
		if (r != KNOT_EOK)
			return r;
	}

	return KNOT_EOK;
}

static int copy_valid_signatures(knot_rrset_t *from, knot_rrset_t *to,
				 const knot_dnssec_policy_t *policy)
{
	assert(from);
	assert(to);
	assert(policy);

	int result = KNOT_EOK;
	uint32_t now = time_now();
	uint32_t refresh = policy->sign_refresh;
	uint32_t expiration;

	for (int i = 0; i < from->rdata_count; i++) {
		expiration = knot_rrset_rdata_rrsig_sig_expiration(from, i);

		// skip expired
		if (expiration < now || expiration - now < refresh)
			continue;

		// copy valid
		result = knot_rrset_add_rr_from_rrset(to, from, i);
		if (result != KNOT_EOK)
			break;
	}

	return result;
}

static int sign_node(const knot_node_t *node, knot_zone_keys_t *zone_keys,
		     const knot_dnssec_policy_t *policy)
{
	assert(node);

	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t *rrset = node->rrset_tree[i];
		knot_rrset_t *rrsigs = rrset->rrsigs;
		knot_rrset_t *new_rrsigs;

		new_rrsigs = create_rrsig_rrset(rrset);
		if (!new_rrsigs)
			return KNOT_ENOMEM;

		assert(knot_dname_compare(rrsigs->owner, new_rrsigs->owner) == 0);
		assert(rrsigs->type == new_rrsigs->type);
		assert(rrsigs->rclass == new_rrsigs->rclass);
		assert(rrsigs->ttl == new_rrsigs->ttl);

		int result = copy_valid_signatures(rrsigs, new_rrsigs, policy);
		if (result != KNOT_EOK) {
			knot_rrset_free(&new_rrsigs);
			return result;
		}

		result = add_missing_signatures(rrset, new_rrsigs, zone_keys, policy);
		if (result != KNOT_EOK) {
			knot_rrset_free(&new_rrsigs);
			return result;
		}

		knot_rrset_free(&rrsigs);
		rrset->rrsigs = new_rrsigs;
	}

	return KNOT_EOK;
}

static bool is_current_key(const knot_key_params_t *key)
{
	time_t now = time(NULL);

	if (now < key->time_activate)
		return false;

	if (key->time_inactive && now > key->time_inactive)
		return false;

	return true;
}

static int load_zone_keys(const char *keydir_name,
			  const knot_dname_t *zone_name,
			  knot_zone_keys_t *keys)
{
	assert(keydir_name);
	assert(zone_name);
	assert(keys);

	DIR *keydir = opendir(keydir_name);
	if (!keydir)
		return KNOT_DNSSEC_EINVALID_KEY;

	struct dirent entry_buf = { 0 };
	struct dirent *entry = NULL;
	while (keys->count < MAX_ZONE_KEYS &&
	       readdir_r(keydir, &entry_buf, &entry) == 0 &&
	       entry != NULL
	) {
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
		if (!path) {
			fprintf(stderr, "failed to alloc key path\n");
			continue;
		}

		snprintf(path, path_len, "%s/%s", keydir_name, entry->d_name);
		fprintf(stderr, "reading key '%s'\n", path);

		knot_key_params_t params = { 0 };
		int result = knot_load_key_params(path, &params);
		free(path);

		if (result != KNOT_EOK) {
			fprintf(stderr, "failed to load key params\n");
			continue;
		}

		if (knot_dname_compare(zone_name, params.name) != 0) {
			fprintf(stderr, "key for other zone\n");
			continue;
		}

		if (!is_current_key(&params)) {
			fprintf(stderr, "key is not active\n");
			continue;
		}

		if (knot_get_key_type(&params) != KNOT_KEY_DNSSEC) {
			fprintf(stderr, "not a DNSSEC key\n");
			continue;
		}

		result = knot_dnssec_key_from_params(&params, &keys->keys[keys->count]);
		if (result != KNOT_EOK) {
			fprintf(stderr, "cannot create the dnssec key\n");
			continue;
		}

		fprintf(stderr, "key is valid\n");
		fprintf(stderr, "key is %s\n", params.flags & 1 ? "ksk" : "zsk");

		keys->is_ksk[keys->count] = params.flags & 1;
		keys->count += 1;
	}

	closedir(keydir);

	return keys->count > 0 ? KNOT_EOK : KNOT_DNSSEC_EINVALID_KEY;
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

int knot_zone_sign(knot_zone_contents_t *zone, const char *keydir)
{
	assert(zone);
	assert(keydir);

	int result;

	knot_dnssec_policy_t policy = DEFAULT_DNSSEC_POLICY;

	knot_zone_keys_t zone_keys;
	memset(&zone_keys, '\0', sizeof(zone_keys));

	result = load_zone_keys(keydir, zone->apex->owner, &zone_keys);
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

	bool sorted = false;
	hattrie_iter_t *it;

	it = hattrie_iter_begin(zone->nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);
		sign_node(node, &zone_keys, &policy);
		hattrie_iter_next(it);
	}
	hattrie_iter_free(it);

	it = hattrie_iter_begin(zone->nsec3_nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);
		sign_node(node, &zone_keys, &policy);
		hattrie_iter_next(it);
	}
	hattrie_iter_free(it);

	free_sign_contexts(&zone_keys);
	return KNOT_EOK;
}
