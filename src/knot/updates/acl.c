/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/updates/acl.h"

bool acl_allowed(conf_t *conf, conf_val_t *acl, acl_action_t action,
                 const struct sockaddr_storage *addr, knot_tsig_key_t *tsig)
{
	if (acl == NULL || addr == NULL || tsig == NULL) {
		return NULL;
	}

	while (acl->code == KNOT_EOK) {
		/* Check if the address matches the current acl address list. */
		conf_val_t val = conf_id_get(conf, C_ACL, C_ADDR, acl);
		if (val.code != KNOT_ENOENT && !conf_addr_range_match(&val, addr)) {
			goto next_acl;
		}

		/* Check if the key matches the current acl key list. */
		conf_val_t key_val = conf_id_get(conf, C_ACL, C_KEY, acl);
		while (key_val.code == KNOT_EOK) {
			/* No key provided, but required. */
			if (tsig->name == NULL) {
				conf_val_next(&key_val);
				continue;
			}

			/* Compare key names (both in lower-case). */
			const knot_dname_t *key_name = conf_dname(&key_val);
			if (!knot_dname_is_equal(key_name, tsig->name)) {
				conf_val_next(&key_val);
				continue;
			}

			/* Compare key algorithms. */
			conf_val_t alg_val = conf_id_get(conf, C_KEY, C_ALG,
			                                 &key_val);
			if (conf_opt(&alg_val) != tsig->algorithm) {
				conf_val_next(&key_val);
				continue;
			}

			break;
		}
		/* Check for key match or empty list without key provided. */
		if (key_val.code != KNOT_EOK &&
		    !(key_val.code == KNOT_ENOENT && tsig->name == NULL)) {
			goto next_acl;
		}

		/* Check if the action is allowed. */
		if (action != ACL_ACTION_NONE) {
			val = conf_id_get(conf, C_ACL, C_ACTION, acl);
			while (val.code == KNOT_EOK) {
				if (conf_opt(&val) != action) {
					conf_val_next(&val);
					continue;
				}

				break;
			}
			switch (val.code) {
			case KNOT_EOK: /* Check for action match. */
				break;
			case KNOT_ENOENT: /* Empty action list allowed with deny only. */
				return false;
			default: /* No match. */
				goto next_acl;
			}
		}

		/* Check if denied. */
		val = conf_id_get(conf, C_ACL, C_DENY, acl);
		if (conf_bool(&val)) {
			return false;
		}

		/* Fill the output with tsig secret if provided. */
		if (tsig->name != NULL) {
			val = conf_id_get(conf, C_KEY, C_SECRET, &key_val);
			tsig->secret.data = (uint8_t *)conf_bin(&val, &tsig->secret.size);
		}

		return true;
next_acl:
		conf_val_next(acl);
	}

	return false;
}
