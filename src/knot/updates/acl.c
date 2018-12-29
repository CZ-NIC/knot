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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot/updates/acl.h"

static bool match_type(uint16_t type, conf_val_t *types)
{
	if (types == NULL) {
		return true;
	}

	conf_val_reset(types);
	while (types->code == KNOT_EOK) {
		if (type == knot_wire_read_u64(types->data)) {
			return true;
		}
		conf_val_next(types);
	}

	return false;
}

static bool match_name(const knot_dname_t *rr_owner, const knot_dname_t *name,
                       acl_update_owner_match_t match)
{
	if (name == NULL) {
		return true;
	}

	int ret = knot_dname_in_bailiwick(rr_owner, name);
	switch (match) {
	case ACL_UPDATE_MATCH_SUBEQ:
		return (ret >= 0);
	case ACL_UPDATE_MATCH_EQ:
		return (ret == 0);
	case ACL_UPDATE_MATCH_SUB:
		return (ret > 0);
	default:
		return false;
	}
}

static bool match_names(const knot_dname_t *rr_owner, conf_val_t *names,
                        acl_update_owner_match_t match)
{
	if (names == NULL) {
		return true;
	}

	conf_val_reset(names);
	while (names->code == KNOT_EOK) {
		if (match_name(rr_owner, conf_dname(names), match)) {
			return true;
		}
		conf_val_next(names);
	}

	return false;
}

static bool update_match(conf_t *conf, conf_val_t *acl, knot_dname_t *key_name,
                         const knot_dname_t *zone_name, knot_pkt_t *query)
{
	if (query == NULL) {
		return true;
	}

	conf_val_t val_types = conf_id_get(conf, C_ACL, C_UPDATE_TYPE, acl);
	conf_val_t *types = (conf_val_count(&val_types) > 0) ? &val_types : NULL;

	conf_val_t val = conf_id_get(conf, C_ACL, C_UPDATE_OWNER, acl);
	acl_update_owner_t owner = conf_opt(&val);

	/* Return if no specific requirements configured. */
	if (types == NULL && owner == ACL_UPDATE_OWNER_NONE) {
		return true;
	}

	acl_update_owner_match_t match = ACL_UPDATE_MATCH_SUBEQ;
	if (owner != ACL_UPDATE_OWNER_NONE) {
		val = conf_id_get(conf, C_ACL, C_UPDATE_OWNER_MATCH, acl);
		match = conf_opt(&val);
	}

	conf_val_t *names = NULL;
	conf_val_t val_names;
	if (owner == ACL_UPDATE_OWNER_NAME) {
		val_names = conf_id_get(conf, C_ACL, C_UPDATE_OWNER_NAME, acl);
		if (conf_val_count(&val_names) > 0) {
			names = &val_names;
		}
	}

	/* Updated RRs are contained in the Authority section of the query
	 * (RFC 2136 Section 2.2)
	 */
	uint16_t pos = query->sections[KNOT_AUTHORITY].pos;
	uint16_t count = query->sections[KNOT_AUTHORITY].count;

	for (int i = pos; i < pos + count; i++) {
		knot_rrset_t *rr = &query->rr[i];
		if (!match_type(rr->type, types)) {
			return false;
		}

		switch (owner) {
		case ACL_UPDATE_OWNER_NAME:
			if (!match_names(rr->owner, names, match)) {
				return false;
			}
			break;
		case ACL_UPDATE_OWNER_KEY:
			if (!match_name(rr->owner, key_name, match)) {
				return false;
			}
			break;
		case ACL_UPDATE_OWNER_ZONE:
			if (!match_name(rr->owner, zone_name, match)) {
				return false;
			}
			break;
		default:
			break;
		}
	}

	return true;
}

bool acl_allowed(conf_t *conf, conf_val_t *acl, acl_action_t action,
                 const struct sockaddr_storage *addr, knot_tsig_key_t *tsig,
                 const knot_dname_t *zone_name, knot_pkt_t *query)
{
	if (acl == NULL || addr == NULL || tsig == NULL) {
		return false;
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

		/* If the action is update, check for update rule match. */
		if (action == ACL_ACTION_UPDATE &&
		    !update_match(conf, acl, tsig->name, zone_name, query)) {
			goto next_acl;
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
