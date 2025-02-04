/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/skip.h"
#include "knot/zone/zonefile.h"

knot_dynarray_define(rrtype, uint16_t, DYNARRAY_VISIBILITY_NORMAL)

// NOTE check against knot_rrtype_is_dnssec()
static uint16_t dnssec_types[] = {
	KNOT_RRTYPE_DNSKEY,
	KNOT_RRTYPE_RRSIG,
	KNOT_RRTYPE_NSEC,
	KNOT_RRTYPE_NSEC3,
	KNOT_RRTYPE_NSEC3PARAM,
	KNOT_RRTYPE_CDNSKEY,
	KNOT_RRTYPE_CDS,
	0
};

static int skip_add(zone_skip_t *skip, uint16_t type)
{
	return rrtype_dynarray_add(skip, &type) == NULL ? KNOT_ENOMEM : KNOT_EOK;
}

static int skip_add_dnssec(zone_skip_t *skip)
{
	int ret = KNOT_EOK;
	for (uint16_t *t = dnssec_types; *t != 0 && ret == KNOT_EOK; t++) {
		ret = skip_add(skip, *t);
	}
	return ret;
}

static int skip_add_string(zone_skip_t *skip, const char *type_str)
{
	if (strncasecmp(type_str, "dnssec", 7) == 0) {
		return skip_add_dnssec(skip);
	} else {
		uint16_t type = 0;
		if (knot_rrtype_from_string(type_str, &type) > -1) {
			return skip_add(skip, type);
		} else {
			return KNOT_EINVAL;
		}
	}
}

static void skip_add_finish(zone_skip_t *skip)
{
	rrtype_dynarray_sort_dedup(skip);
}

int zone_skip_add(zone_skip_t *skip, const char *type_str)
{
	int ret = skip_add_string(skip, type_str);
	skip_add_finish(skip);
	return ret;
}

int zone_skip_from_conf(zone_skip_t *skip, conf_val_t *val)
{
	int ret = KNOT_EOK;

	while (val->code == KNOT_EOK && ret == KNOT_EOK) {
		ret = skip_add_string(skip, conf_str(val));
		conf_val_next(val);
	}

	if (val->code == KNOT_EOF) {
		conf_val_reset(val);
	}
	skip_add_finish(skip);

	if (ret != KNOT_EOK) {
		zone_skip_free(skip);
	}

	return ret;
}

int zonefile_write_skip(const char *path, struct zone_contents *zone, conf_t *conf)
{
	conf_val_t skip_val = conf_zone_get(conf, C_ZONEFILE_SKIP, zone->apex->owner);
	zone_skip_t skip = { 0 };
	int ret = zone_skip_from_conf(&skip, &skip_val);
	if (ret == KNOT_EOK) {
		ret = zonefile_write(path, zone, &skip);
	}
	zone_skip_free(&skip);
	return ret;
}
