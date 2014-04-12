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
#include <string.h>

#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/dnssec/key.h"
#include "libknot/rdata/tsig.h"

/*!
 * \brief Creates TSIG key.
 */
int knot_tsig_create_key(const char *name, int algorithm,
                         const char *b64secret, knot_tsig_key_t *key)
{
	if (!name || !b64secret || !key) {
		return KNOT_EINVAL;
	}

	knot_dname_t *dname;
	dname = knot_dname_from_str(name);
	if (!dname) {
		return KNOT_ENOMEM;
	}

	knot_binary_t secret;
	int result = knot_binary_from_base64(b64secret, &secret);
	if (result != KNOT_EOK) {
		knot_dname_free(&dname, NULL);
		return result;
	}

	key->name = dname;
	key->algorithm = algorithm;
	key->secret = secret;

	return KNOT_EOK;
}

/*!
 * \brief Frees TSIG key.
 */
int knot_tsig_key_free(knot_tsig_key_t *key)
{
	if (!key) {
		return KNOT_EINVAL;
	}

	knot_dname_free(&key->name, NULL);
	knot_binary_free(&key->secret);
	memset(key, '\0', sizeof(knot_tsig_key_t));

	return KNOT_EOK;
}

int knot_copy_key_params(const knot_key_params_t *src, knot_key_params_t *dst)
{
	if (src == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	knot_key_params_t copy = { 0 };
	copy.algorithm = src->algorithm;

	if (src->name) {
		copy.name = knot_dname_copy(src->name, NULL);
		if (!copy.name) {
			return KNOT_ENOMEM;
		}
	}

	int ret = knot_binary_dup(&src->secret, &copy.secret);
	if (ret != KNOT_EOK) {
		knot_dname_free(&copy.name, NULL);
	}

	*dst = copy;

	return KNOT_EOK;
}

int knot_free_key_params(knot_key_params_t *key_params)
{
	if (!key_params) {
		return KNOT_EINVAL;
	}

	knot_dname_free(&key_params->name, NULL);
	knot_binary_free(&key_params->secret);

	memset(key_params, '\0', sizeof(*key_params));

	return KNOT_EOK;
}


int knot_tsig_key_from_params(const knot_key_params_t *params,
                              knot_tsig_key_t *key_ptr)
{
	if (!params || !key_ptr) {
		return KNOT_EINVAL;
	}

	knot_tsig_key_t key = { 0 };

	key.algorithm = params->algorithm;

	key.name = knot_dname_copy(params->name, NULL);
	if (!key.name) {
		return KNOT_ENOMEM;
	}

	int result = knot_binary_dup(&params->secret, &key.secret);
	if (result != KNOT_EOK) {
		knot_dname_free(&key.name, NULL);
		return result;
	}

	*key_ptr = key;

	return KNOT_EOK;
}
