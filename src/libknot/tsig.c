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
#include <string.h>

#include "contrib/getline.h"
#include "contrib/string.h"
#include "dnssec/error.h"
#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/tsig.h"

_public_
void knot_tsig_key_deinit(knot_tsig_key_t *key)
{
	if (!key) {
		return;
	}

	knot_dname_free(&key->name, NULL);

	memset(key->secret.data, 0, key->secret.size);
	dnssec_binary_free(&key->secret);

	memset(key, '\0', sizeof(*key));
}

_public_
int knot_tsig_key_init(knot_tsig_key_t *key, const char *algorithm_name,
                       const char *name, const char *secret_b64)
{
	if (!name || !secret_b64 || !key) {
		return KNOT_EINVAL;
	}

	dnssec_tsig_algorithm_t algorithm = DNSSEC_TSIG_HMAC_SHA256;
	if (algorithm_name != NULL) {
		algorithm = dnssec_tsig_algorithm_from_name(algorithm_name);
		if (algorithm == DNSSEC_TSIG_UNKNOWN) {
			return KNOT_EMALF;
		}
	}

	knot_dname_t *dname = knot_dname_from_str_alloc(name);
	if (!dname) {
		return KNOT_ENOMEM;
	}
	knot_dname_to_lower(dname);

	dnssec_binary_t b64secret = { 0 };
	b64secret.data = (uint8_t *)secret_b64;
	b64secret.size = strlen(secret_b64);

	dnssec_binary_t secret = { 0 };
	int result = dnssec_binary_from_base64(&b64secret, &secret);
	if (result != KNOT_EOK) {
		knot_dname_free(&dname, NULL);
		return result;
	}

	key->name = dname;
	key->algorithm = algorithm;
	key->secret = secret;

	return KNOT_EOK;
}

_public_
int knot_tsig_key_init_str(knot_tsig_key_t *key, const char *params)
{
	if (!params) {
		return KNOT_EINVAL;
	}

	char *copy = strstrip(params);
	if (!copy) {
		return KNOT_ENOMEM;
	}

	size_t copy_size = strlen(copy) + 1;

	// format [algorithm:]name:secret

	char *algorithm = NULL;
	char *name = NULL;
	char *secret = NULL;

	// find secret

	char *pos = strrchr(copy, ':');
	if (pos) {
		*pos = '\0';
		secret = pos + 1;
	} else {
		memset(copy, 0, copy_size);
		free(copy);
		return KNOT_EMALF;
	}

	// find name and optionally algorithm

	pos = strchr(copy, ':');
	if (pos) {
		*pos = '\0';
		algorithm = copy;
		name = pos + 1;
	} else {
		name = copy;
	}

	int result = knot_tsig_key_init(key, algorithm, name, secret);

	memset(copy, 0, copy_size);
	free(copy);

	return result;
}

_public_
int knot_tsig_key_init_file(knot_tsig_key_t *key, const char *filename)
{
	if (!filename) {
		return KNOT_EINVAL;
	}

	FILE *file = fopen(filename, "r");
	if (!file) {
		return KNOT_EACCES;
	}

	char *line = NULL;
	size_t line_size = 0;
	ssize_t read = knot_getline(&line, &line_size, file);

	fclose(file);

	if (read == -1) {
		return KNOT_EMALF;
	}

	int result = knot_tsig_key_init_str(key, line);

	memset(line, 0, line_size);
	free(line);

	return result;
}

_public_
int knot_tsig_key_copy(knot_tsig_key_t *dst, const knot_tsig_key_t *src)
{
	if (!src || !dst) {
		return KNOT_EINVAL;
	}

	knot_tsig_key_t copy = { 0 };
	copy.algorithm = src->algorithm;

	copy.name = knot_dname_copy(src->name, NULL);
	if (!copy.name) {
		return KNOT_ENOMEM;
	}

	if (dnssec_binary_dup(&src->secret, &copy.secret) != DNSSEC_EOK) {
		knot_tsig_key_deinit(&copy);
		return KNOT_ENOMEM;
	}

	*dst = copy;

	return KNOT_EOK;
}
