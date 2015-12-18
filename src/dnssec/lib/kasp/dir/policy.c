/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "error.h"
#include "json.h"
#include "kasp.h"
#include "policy.h"
#include "shared.h"

static const encode_attr_t POLICY_ATTRS[] = {
	#define attr(name) #name, offsetof(dnssec_kasp_policy_t, name)
	{ attr(keystore),             encode_string, decode_string },
	{ attr(manual),               encode_bool,   decode_bool   },
	{ attr(algorithm),            encode_uint8,  decode_uint8  },
	{ attr(ksk_size),             encode_uint16, decode_uint16 },
	{ attr(zsk_size),             encode_uint16, decode_uint16 },
	{ attr(dnskey_ttl),           encode_uint32, decode_uint32 },
	{ attr(zsk_lifetime),         encode_uint32, decode_uint32 },
	{ attr(rrsig_lifetime),       encode_uint32, decode_uint32 },
	{ attr(rrsig_refresh_before), encode_uint32, decode_uint32 },
	{ attr(nsec3_enabled),        encode_bool,   decode_bool   },
	{ attr(soa_minimal_ttl),      encode_uint32, decode_uint32 },
	{ attr(zone_maximal_ttl),     encode_uint32, decode_uint32 },
	{ attr(propagation_delay),    encode_uint32, decode_uint32 },
	{ NULL }
	#undef attr
};

int load_policy_config(dnssec_kasp_policy_t *policy, const char *filename)
{
	assert(policy);
	assert(filename);

	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	json_error_t error = { 0 };
	_json_cleanup_ json_t *config = json_loadf(file, JSON_LOAD_OPTIONS, &error);
	if (!config) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	return decode_object(POLICY_ATTRS, config, policy);
}

int save_policy_config(dnssec_kasp_policy_t *policy, const char *filename)
{
	assert(policy);
	assert(filename);

	_json_cleanup_ json_t *config = NULL;
	int r = encode_object(POLICY_ATTRS, policy, &config);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_cleanup_fclose_ FILE *file = fopen(filename, "w");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	r = json_dumpf(config, file, JSON_DUMP_OPTIONS);
	if (r != DNSSEC_EOK) {
		return r;
	}

	fputc('\n', file);
	return DNSSEC_EOK;
}
