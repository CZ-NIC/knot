/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>

#include "knot/catalog/generate.h"
#include "knot/common/log.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/zonedb.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/wire_ctx.h"

static knot_dname_t *catalog_member_owner(const knot_dname_t *member,
                                          const knot_dname_t *catzone,
                                          time_t member_time)
{
	SIPHASH_CTX hash;
	SIPHASH_KEY shkey = { 0 }; // only used for hashing -> zero key
	SipHash24_Init(&hash, &shkey);
	SipHash24_Update(&hash, member, knot_dname_size(member));
	uint64_t u64time = htobe64(member_time);
	SipHash24_Update(&hash, &u64time, sizeof(u64time));
	uint64_t hashres = SipHash24_End(&hash);

	char *hexhash = bin_to_hex((uint8_t *)&hashres, sizeof(hashres));
	if (hexhash == NULL) {
		return NULL;
	}
	size_t hexlen = strlen(hexhash);
	assert(hexlen == 16);
	size_t zoneslen = knot_dname_size((uint8_t *)CATALOG_ZONES_LABEL);
	assert(hexlen <= KNOT_DNAME_MAXLABELLEN && zoneslen <= KNOT_DNAME_MAXLABELLEN);
	size_t catzlen = knot_dname_size(catzone);

	size_t outlen = hexlen + zoneslen + catzlen;
	knot_dname_t *out;
	if (outlen > KNOT_DNAME_MAXLEN || (out = malloc(outlen)) == NULL) {
		free(hexhash);
		return NULL;
	}

	wire_ctx_t wire = wire_ctx_init(out, outlen);
	wire_ctx_write_u8(&wire, hexlen);
	wire_ctx_write(&wire, hexhash, hexlen);
	wire_ctx_write(&wire, CATALOG_ZONES_LABEL, zoneslen);
	wire_ctx_skip(&wire, -1);
	wire_ctx_write(&wire, catzone, catzlen);
	assert(wire.error == KNOT_EOK);

	free(hexhash);
	return out;
}

static bool same_group(zone_t *old_z, zone_t *new_z)
{
	if (old_z->catalog_group == NULL || new_z->catalog_group == NULL) {
		return (old_z->catalog_group == new_z->catalog_group);
	} else {
		return (strcmp(old_z->catalog_group, new_z->catalog_group) == 0);
	}
}

void catalogs_generate(struct knot_zonedb *db_new, struct knot_zonedb *db_old)
{
	// general comment: catz->contents!=NULL means incremental update of catalog

	if (db_old != NULL) {
		knot_zonedb_iter_t *it = knot_zonedb_iter_begin(db_old);
		while (!knot_zonedb_iter_finished(it)) {
			zone_t *zone = knot_zonedb_iter_val(it);
			knot_dname_t *cg = zone->catalog_gen;
			if (cg != NULL && knot_zonedb_find(db_new, zone->name) == NULL) {
				zone_t *catz = knot_zonedb_find(db_new, cg);
				if (catz != NULL && catz->contents != NULL) {
					assert(catz->cat_members != NULL); // if this failed to allocate, catz wasn't added to zonedb
					knot_dname_t *owner = catalog_member_owner(zone->name, cg, zone->timers.catalog_member);
					if (owner == NULL) {
						catz->cat_members->error = KNOT_ENOENT;
						knot_zonedb_iter_next(it);
						continue;
					}
					int ret = catalog_update_add(catz->cat_members, zone->name, owner,
					                             cg, CAT_UPD_REM, NULL, 0, NULL);
					free(owner);
					if (ret != KNOT_EOK) {
						catz->cat_members->error = ret;
					} else {
						zone_events_schedule_now(catz, ZONE_EVENT_LOAD);
					}
				}
			}
			knot_zonedb_iter_next(it);
		}
		knot_zonedb_iter_free(it);
	}

	knot_zonedb_iter_t *it = knot_zonedb_iter_begin(db_new);
	while (!knot_zonedb_iter_finished(it)) {
		zone_t *zone = knot_zonedb_iter_val(it);
		knot_dname_t *cg = zone->catalog_gen;
		if (cg == NULL) {
			knot_zonedb_iter_next(it);
			continue;
		}
		zone_t *catz = knot_zonedb_find(db_new, cg);
		zone_t *old = knot_zonedb_find(db_old, zone->name);
		knot_dname_t *owner = catalog_member_owner(zone->name, cg, zone->timers.catalog_member);
		size_t cgroup_size = zone->catalog_group == NULL ? 0 : strlen(zone->catalog_group);
		if (catz == NULL) {
			log_zone_warning(zone->name, "member zone belongs to non-existing catalog zone");
		} else if (catz->contents == NULL || old == NULL) {
			assert(catz->cat_members != NULL);
			if (owner == NULL) {
				catz->cat_members->error = KNOT_ENOENT;
				knot_zonedb_iter_next(it);
				continue;
			}
			int ret = catalog_update_add(catz->cat_members, zone->name, owner,
			                             cg, CAT_UPD_ADD, zone->catalog_group,
			                             cgroup_size, NULL);
			if (ret != KNOT_EOK) {
				catz->cat_members->error = ret;
			} else {
				zone_events_schedule_now(catz, ZONE_EVENT_LOAD);
			}
		} else if (!same_group(zone, old)) {
			int ret = catalog_update_add(catz->cat_members, zone->name, owner,
			                             cg, CAT_UPD_PROP, zone->catalog_group,
			                             cgroup_size, NULL);
			if (ret != KNOT_EOK) {
				catz->cat_members->error = ret;
			} else {
				zone_events_schedule_now(catz, ZONE_EVENT_LOAD);
			}
		}
		free(owner);
		knot_zonedb_iter_next(it);
	}
	knot_zonedb_iter_free(it);
}

static void set_rdata(knot_rrset_t *rrset, uint8_t *data, uint16_t len)
{
	knot_rdata_init(rrset->rrs.rdata, len, data);
	rrset->rrs.size = knot_rdata_size(len);
}

#define def_txt_owner(ptr_owner) \
	knot_dname_storage_t txt_owner = "\x05""group"; \
	size_t _ptr_ow_len = knot_dname_size(ptr_owner); \
	size_t _ptr_ow_ind = strlen((const char *)txt_owner); \
	if (_ptr_ow_ind + _ptr_ow_len > sizeof(txt_owner)) { \
		return KNOT_ERANGE; \
	} \
	memcpy(txt_owner + _ptr_ow_ind, (ptr_owner), _ptr_ow_len);

static int add_group_txt(const knot_dname_t *ptr_owner, const char *group,
                         zone_contents_t *conts, zone_update_t *up)
{
	assert((conts == NULL) != (up == NULL));
	size_t group_len;
	if (group == NULL || (group_len = strlen(group)) < 1) {
		return KNOT_EOK;
	}
	assert(group_len <= 255);

	def_txt_owner(ptr_owner);

	uint8_t data[256] = { group_len };
	memcpy(data + 1, group, group_len);

	knot_rrset_t txt;
	knot_rrset_init(&txt, txt_owner, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, 0);
	uint8_t txt_rd[256] = { 0 };
	txt.rrs.rdata = (knot_rdata_t *)txt_rd;
	txt.rrs.count = 1;
	set_rdata(&txt, data, 1 + group_len );

	int ret;
	if (conts != NULL) {
		zone_node_t *unused = NULL;
		ret = zone_contents_add_rr(conts, &txt, &unused);
	} else {
		ret = zone_update_add(up, &txt);
	}

	return ret;
}

static int rem_group_txt(const knot_dname_t *ptr_owner, zone_update_t *up)
{
	def_txt_owner(ptr_owner);

	int ret = zone_update_remove_rrset(up, txt_owner, KNOT_RRTYPE_TXT);
	if (ret == KNOT_ENOENT || ret == KNOT_ENONODE) {
		ret = KNOT_EOK;
	}

	return ret;
}

struct zone_contents *catalog_update_to_zone(catalog_update_t *u, const knot_dname_t *catzone,
                                             uint32_t soa_serial)
{
	if (u->error != KNOT_EOK) {
		return NULL;
	}
	zone_contents_t *c = zone_contents_new(catzone, true);
	if (c == NULL) {
		return c;
	}

	zone_node_t *unused = NULL;
	uint8_t invalid[9] = "\x07""invalid";
	uint8_t version[9] = "\x07""version";
	uint8_t cat_version[2] = "\x01" CATALOG_ZONE_VERSION;

	// prepare common rrset with one rdata item
	uint8_t rdata[256] = { 0 };
	knot_rrset_t rrset;
	knot_rrset_init(&rrset, (knot_dname_t *)catzone, KNOT_RRTYPE_SOA, KNOT_CLASS_IN, 0);
	rrset.rrs.rdata = (knot_rdata_t *)rdata;
	rrset.rrs.count = 1;

	// set catalog zone's SOA
	uint8_t data[250];
	assert(sizeof(knot_rdata_t) + sizeof(data) <= sizeof(rdata));
	wire_ctx_t wire = wire_ctx_init(data, sizeof(data));
	wire_ctx_write(&wire, invalid, sizeof(invalid));
	wire_ctx_write(&wire, invalid, sizeof(invalid));
	wire_ctx_write_u32(&wire, soa_serial);
	wire_ctx_write_u32(&wire, CATALOG_SOA_REFRESH);
	wire_ctx_write_u32(&wire, CATALOG_SOA_RETRY);
	wire_ctx_write_u32(&wire, CATALOG_SOA_EXPIRE);
	wire_ctx_write_u32(&wire, 0);
	set_rdata(&rrset, data, wire_ctx_offset(&wire));
	if (zone_contents_add_rr(c, &rrset, &unused) != KNOT_EOK) {
		goto fail;
	}

	// set catalog zone's NS
	unused = NULL;
	rrset.type = KNOT_RRTYPE_NS;
	set_rdata(&rrset, invalid, sizeof(invalid));
	if (zone_contents_add_rr(c, &rrset, &unused) != KNOT_EOK) {
		goto fail;
	}

	// set catalog zone's version TXT
	unused = NULL;
	knot_dname_storage_t owner;
	if (knot_dname_store(owner, version) == 0 || catalog_dname_append(owner, catzone) == 0) {
		goto fail;
	}
	rrset.owner = owner;
	rrset.type = KNOT_RRTYPE_TXT;
	set_rdata(&rrset, cat_version, sizeof(cat_version));
	if (zone_contents_add_rr(c, &rrset, &unused) != KNOT_EOK) {
		goto fail;
	}

	// insert member zone PTR records
	rrset.type = KNOT_RRTYPE_PTR;
	catalog_it_t *it = catalog_it_begin(u);
	while (!catalog_it_finished(it)) {
		catalog_upd_val_t *val = catalog_it_val(it);
		if (val->add_owner == NULL) {
			continue;
		}
		rrset.owner = val->add_owner;
		set_rdata(&rrset, val->member, knot_dname_size(val->member));
		unused = NULL;
		if (zone_contents_add_rr(c, &rrset, &unused) != KNOT_EOK ||
		    add_group_txt(val->add_owner, val->new_group, c, NULL) != KNOT_EOK) {
			catalog_it_free(it);
			goto fail;
		}
		catalog_it_next(it);
	}
	catalog_it_free(it);

	return c;
fail:
	zone_contents_deep_free(c);
	return NULL;
}

int catalog_update_to_update(catalog_update_t *u, struct zone_update *zu)
{
	knot_rrset_t ptr;
	knot_rrset_init(&ptr, NULL, KNOT_RRTYPE_PTR, KNOT_CLASS_IN, 0);
	uint8_t tmp[KNOT_DNAME_MAXLEN + sizeof(knot_rdata_t)];
	ptr.rrs.rdata = (knot_rdata_t *)tmp;
	ptr.rrs.count = 1;

	int ret = u->error;
	catalog_it_t *it = catalog_it_begin(u);
	while (!catalog_it_finished(it) && ret == KNOT_EOK) {
		catalog_upd_val_t *val = catalog_it_val(it);
		if (val->type == CAT_UPD_INVALID) {
			catalog_it_next(it);
			continue;
		}

		if (val->type == CAT_UPD_PROP && knot_dname_is_equal(zu->zone->name, val->add_catz)) {
			ret = rem_group_txt(val->add_owner, zu);
			if (ret == KNOT_EOK) {
				ret = add_group_txt(val->add_owner, val->new_group, NULL, zu);
			}
			catalog_it_next(it);
			continue;
		}

		set_rdata(&ptr, val->member, knot_dname_size(val->member));
		if (val->type == CAT_UPD_REM && knot_dname_is_equal(zu->zone->name, val->rem_catz)) {
			ptr.owner = val->rem_owner;
			ret = zone_update_remove(zu, &ptr);
			if (ret == KNOT_EOK) {
				ret = rem_group_txt(val->rem_owner, zu);
			}
		}
		if (val->type == CAT_UPD_ADD && knot_dname_is_equal(zu->zone->name, val->add_catz)) {
			ptr.owner = val->add_owner;
			ret = zone_update_add(zu, &ptr);
			if (ret == KNOT_EOK) {
				ret = add_group_txt(val->add_owner, val->new_group, NULL, zu);
			}
		}
		catalog_it_next(it);
	}
	catalog_it_free(it);
	return ret;
}
