/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "kasp/dir/json.h"
#include "kasp/dir/keystore.h"
#include "kasp/internal.h"
#include "shared.h"

static const encode_attr_t ATTRIBUTES[] = {
	#define off(member) offsetof(dnssec_kasp_keystore_t, member)
	{ "backend", off(backend), encode_string, decode_string },
	{ "config",  off(config),  encode_string, decode_string },
	{ NULL }
};

static bool keystore_valid(dnssec_kasp_keystore_t *keystore)
{
	assert(keystore);
	return keystore->backend && keystore->config;
}

static int import_keystore(dnssec_kasp_keystore_t *keystore, const json_t *json)
{
	dnssec_kasp_keystore_t result = { 0 };
	int r = decode_object(ATTRIBUTES, json, &result);
	if (r != DNSSEC_EOK) {
		return r;
	}

	if (!keystore_valid(&result)) {
		kasp_keystore_cleanup(&result);
		return DNSSEC_CONFIG_MALFORMED;
	}

	result.name = keystore->name;
	*keystore = result;

	return DNSSEC_EOK;
}

static int export_keystore(dnssec_kasp_keystore_t *keystore, json_t **json)
{
	assert(keystore);
	assert(json);

	if (!keystore_valid(keystore)) {
		return DNSSEC_EINVAL;
	}

	return encode_object(ATTRIBUTES, keystore, json);
}

/* -- internal API --------------------------------------------------------- */

int load_keystore_config(dnssec_kasp_keystore_t *keystore, const char *filename)
{
	assert(keystore);
	assert(filename);

	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	json_error_t error = { 0 };
	_json_cleanup_ json_t *json = json_loadf(file, JSON_LOAD_OPTIONS, &error);
	if (!json) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	return import_keystore(keystore, json);
}

int save_keystore_config(dnssec_kasp_keystore_t *keystore, const char *filename)
{
	assert(keystore);
	assert(filename);

	_json_cleanup_ json_t *json = NULL;
	int r = export_keystore(keystore, &json);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_cleanup_fclose_ FILE *file = fopen(filename, "w");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	r = json_dumpf(json, file, JSON_DUMP_OPTIONS);
	if (r != DNSSEC_EOK) {
		return r;
	}

	fputc('\n', file);
	return DNSSEC_EOK;
}
