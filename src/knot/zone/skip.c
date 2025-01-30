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

int zone_skip_from_conf(zone_skip_t *skip, conf_val_t *val)
{
	int ret = KNOT_EOK;

	while (val->code == KNOT_EOK && ret == KNOT_EOK) {
		const char *type_s = conf_str(val);
		if (strncasecmp(type_s, "dnssec", 7) == 0) {
			for (uint16_t *t = dnssec_types; *t != 0 && ret == KNOT_EOK; t++) {
				ret = skip_add(skip, *t);
			}
		} else {
			uint16_t type = 0;
			ret = knot_rrtype_from_string(type_s, &type);
			if (ret > -1) {
				ret = skip_add(skip, type);
			} else {
				ret = KNOT_ENOENT;
			}
		}
		conf_val_next(val);
	}

	if (val->code == KNOT_EOF) {
		conf_val_reset(val);
	}
	rrtype_dynarray_sort_dedup(skip);

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
