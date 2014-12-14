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

#include "dnssec/binary.h"
#include "libknot/dnssec/key.h"

#include "libknot/internal/getline.h"
#include "libknot/internal/macros.h"

#include "zscanner/scanner.h"		// TODO: remove dependency!!

#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/binary.h"
#include "libknot/dname.h"
#include "libknot/dnssec/key.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/tsig.h"

/*!
 * \brief Creates TSIG key.
 */
_public_
int knot_tsig_create_key(const char *name, dnssec_tsig_algorithm_t algorithm,
                         const char *b64secret_str, knot_tsig_key_t *key)
{
	if (!name || !b64secret_str || !key) {
		return KNOT_EINVAL;
	}

	knot_dname_t *dname;
	dname = knot_dname_from_str_alloc(name);
	if (!dname) {
		return KNOT_ENOMEM;
	}

	dnssec_binary_t b64secret = { 0 };
	b64secret.data = (uint8_t *)b64secret_str;
	b64secret.size = strlen(b64secret_str);

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

/*!
 * \brief Frees TSIG key.
 */
_public_
int knot_tsig_key_free(knot_tsig_key_t *key)
{
	if (!key) {
		return KNOT_EINVAL;
	}

	knot_dname_free(&key->name, NULL);
	dnssec_binary_free(&key->secret);
	memset(key, '\0', sizeof(knot_tsig_key_t));

	return KNOT_EOK;
}

_public_
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

	int ret = dnssec_binary_dup(&src->secret, &copy.secret);
	if (ret != KNOT_EOK) {
		knot_dname_free(&copy.name, NULL);
	}

	*dst = copy;

	return KNOT_EOK;
}

_public_
int knot_free_key_params(knot_key_params_t *key_params)
{
	if (!key_params) {
		return KNOT_EINVAL;
	}

	knot_dname_free(&key_params->name, NULL);
	dnssec_binary_free(&key_params->secret);

	memset(key_params, '\0', sizeof(*key_params));

	return KNOT_EOK;
}

_public_
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

	int result = dnssec_binary_dup(&params->secret, &key.secret);
	if (result != KNOT_EOK) {
		knot_dname_free(&key.name, NULL);
		return result;
	}

	*key_ptr = key;

	return KNOT_EOK;
}
