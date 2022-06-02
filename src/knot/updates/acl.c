/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/wire_ctx.h"

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

static bool match_names(const knot_dname_t *rr_owner, const knot_dname_t *zone_name,
                        conf_val_t *names, acl_update_owner_match_t match)
{
	if (names == NULL) {
		return true;
	}

	conf_val_reset(names);
	while (names->code == KNOT_EOK) {
		knot_dname_storage_t full_name;
		size_t len;
		const uint8_t *name = conf_data(names, &len);
		if (name[len - 1] != '\0') {
			// Append zone name if non-FQDN.
			wire_ctx_t ctx = wire_ctx_init(full_name, sizeof(full_name));
			wire_ctx_write(&ctx, name, len);
			wire_ctx_write(&ctx, zone_name, knot_dname_size(zone_name));
			if (ctx.error != KNOT_EOK) {
				return false;
			}
			name = full_name;
		}
		if (match_name(rr_owner, name, match)) {
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
			if (!match_names(rr->owner, zone_name, names, match)) {
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

static bool check_addr_key(conf_t *conf, conf_val_t *addr_val, conf_val_t *key_val,
                           bool remote, const struct sockaddr_storage *addr,
                           const knot_tsig_key_t *tsig, bool deny)
{
	/* Check if the address matches the acl address list or remote addresses. */
	if (addr_val->code != KNOT_ENOENT) {
		if (remote) {
			if (!conf_addr_match(addr_val, addr)) {
				return false;
			}
		} else {
			if (!conf_addr_range_match(addr_val, addr)) {
				return false;
			}
		}
	}

	/* Check if the key matches the acl key list or remote key. */
	while (key_val->code == KNOT_EOK) {
		/* No key provided, but required. */
		if (tsig->name == NULL) {
			goto next_key;
		}

		/* Compare key names (both in lower-case). */
		const knot_dname_t *key_name = conf_dname(key_val);
		if (!knot_dname_is_equal(key_name, tsig->name)) {
			goto next_key;
		}

		/* Compare key algorithms. */
		conf_val_t alg_val = conf_id_get(conf, C_KEY, C_ALG, key_val);
		if (conf_opt(&alg_val) != tsig->algorithm) {
			goto next_key;
		}

		break;
	next_key:
		if (remote) {
			assert(!(key_val->item->flags & YP_FMULTI));
			key_val->code = KNOT_EOF;
			break;
		} else {
			assert(key_val->item->flags & YP_FMULTI);
			conf_val_next(key_val);
		}
	}
	switch (key_val->code) {
	case KNOT_EOK:
		// Key match.
		break;
	case KNOT_ENOENT:
		// Empty list without key provided or denied.
		if (tsig->name == NULL || deny) {
			break;
		}
		// FALLTHROUGH
	default:
		return false;
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
		conf_val_t rmt_val = conf_id_get(conf, C_ACL, C_RMT, acl);
		bool remote = (rmt_val.code == KNOT_EOK);
		conf_val_t deny_val = conf_id_get(conf, C_ACL, C_DENY, acl);
		bool deny = conf_bool(&deny_val);

		/* Check if a remote matches given address and key. */
		conf_val_t addr_val, key_val;
		conf_mix_iter_t iter;
		conf_mix_iter_init(conf, &rmt_val, &iter);
		while (iter.id->code == KNOT_EOK) {
			addr_val = conf_id_get(conf, C_RMT, C_ADDR, iter.id);
			key_val = conf_id_get(conf, C_RMT, C_KEY, iter.id);
			if (check_addr_key(conf, &addr_val, &key_val, remote, addr, tsig, deny)) {
				break;
			}
			conf_mix_iter_next(&iter);
		}
		if (iter.id->code == KNOT_EOF) {
			goto next_acl;
		}
		/* Or check if acl address/key matches given address and key. */
		if (!remote) {
			addr_val = conf_id_get(conf, C_ACL, C_ADDR, acl);
			key_val = conf_id_get(conf, C_ACL, C_KEY, acl);
			if (!check_addr_key(conf, &addr_val, &key_val, remote, addr, tsig, deny)) {
				goto next_acl;
			}
		}

		/* Check if the action is allowed. */
		if (action != ACL_ACTION_QUERY) {
			conf_val_t val = conf_id_get(conf, C_ACL, C_ACTION, acl);
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
		if (deny) {
			return false;
		}

		/* Fill the output with tsig secret if provided. */
		if (tsig->name != NULL) {
			conf_val_t val = conf_id_get(conf, C_KEY, C_SECRET, &key_val);
			tsig->secret.data = (uint8_t *)conf_bin(&val, &tsig->secret.size);
		}

		return true;
next_acl:
		conf_val_next(acl);
	}

	return false;
}

bool rmt_allowed(conf_t *conf, conf_val_t *rmts, const struct sockaddr_storage *addr,
                 knot_tsig_key_t *tsig)
{
	if (!conf->cache.srv_auto_acl) {
		return false;
	}

	conf_mix_iter_t iter;
	conf_mix_iter_init(conf, rmts, &iter);
	while (iter.id->code == KNOT_EOK) {
		conf_val_t val = conf_id_get(conf, C_RMT, C_AUTO_ACL, iter.id);
		if (!conf_bool(&val)) {
			goto next_remote;
		}

		conf_val_t key_id = conf_id_get(conf, C_RMT, C_KEY, iter.id);
		if (key_id.code == KNOT_EOK) {
			/* No key provided, but required. */
			if (tsig->name == NULL) {
				goto next_remote;
			}

			/* Compare key names (both in lower-case). */
			const knot_dname_t *key_name = conf_dname(&key_id);
			if (!knot_dname_is_equal(key_name, tsig->name)) {
				goto next_remote;
			}

			/* Compare key algorithms. */
			val = conf_id_get(conf, C_KEY, C_ALG, &key_id);
			if (conf_opt(&val) != tsig->algorithm) {
				goto next_remote;
			}
		} else if (key_id.code == KNOT_ENOENT && tsig->name != NULL)  {
			/* Key provided but no key configured. */
			goto next_remote;
		}

		/* Check if the address matches. */
		val = conf_id_get(conf, C_RMT, C_ADDR, iter.id);
		if (!conf_addr_match(&val, addr)) {
			goto next_remote;
		}

		/* Fill out the output with tsig secret if provided. */
		if (tsig->name != NULL) {
			val = conf_id_get(conf, C_KEY, C_SECRET, &key_id);
			tsig->secret.data = (uint8_t *)conf_bin(&val, &tsig->secret.size);
		}

		return true;
next_remote:
		conf_mix_iter_next(&iter);
	}

	return false;
}
