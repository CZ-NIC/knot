/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/updates/acl.h"

#include "contrib/string.h"
#include "contrib/wire_ctx.h"

static bool cert_pin_check(const uint8_t *session_pin, size_t session_pin_size,
                           conf_val_t *pins)
{
	if (pins->code == KNOT_ENOENT) { // No certificate pin authentication required.
		return true;
	} else if (session_pin_size == 0) { // Not a TLS/QUIC connection.
		return false;
	}

	while (pins->code == KNOT_EOK) {
		size_t pin_size;
		const uint8_t *pin = conf_bin(pins, &pin_size);
		if (pin_size == session_pin_size &&
		    const_time_memcmp(pin, session_pin, pin_size) == 0) {
			return true;
		}
		conf_val_next(pins);
	}

	return false;
}

static bool cert_check(struct gnutls_session_int *tls_session, conf_val_t *hostname_val, bool single)
{
	// cert verification wasn't requested
	if (hostname_val == NULL) {
		return true;
	}

	// at least one item must be present
	assert(hostname_val->code == KNOT_EOK);

	size_t nhostnames = conf_val_count(hostname_val);
	const char *hostnames[nhostnames];

	for (size_t i = 0; i < nhostnames && hostname_val->code == KNOT_EOK; ++i) {
		hostnames[i] = conf_str(hostname_val);
		if (single) {
			break;
		}
		conf_val_next(hostname_val);
	}

	return knot_tls_cert_check(tls_session, nhostnames, hostnames) == KNOT_EOK;
}

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

static bool match_pattern(const knot_dname_t *rr_owner, const knot_dname_t *name)
{
	while (true) {
		uint8_t name_len = *name++;
		uint8_t owner_len = *rr_owner++;

		if (name_len == 1 && *name == '*') {
			if (owner_len == 0) {
				return false;
			}
		} else if (name_len != owner_len) {
			return false;
		} else if (name_len == 0) {
			assert(owner_len == 0);
			return true;
		} else if (memcmp(name, rr_owner, name_len) != 0) {
			return false;
		}

		name += name_len;
		rr_owner += owner_len;
	}
}

static bool match_name(const knot_dname_t *rr_owner, const knot_dname_t *name,
                       acl_update_owner_match_t match)
{
	if (name == NULL) {
		return true;
	}

	if (match == ACL_UPDATE_MATCH_PATTERN) {
		return match_pattern(rr_owner, name);
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

static bool check_proto_rmt(conf_t *conf, knotd_query_proto_t proto, conf_val_t *rmt_id)
{
	conf_val_t quic_val = conf_id_get(conf, C_RMT, C_QUIC, rmt_id);
	if (conf_bool(&quic_val)) {
		return proto == KNOTD_QUERY_PROTO_QUIC;
	}

	conf_val_t tls_val = conf_id_get(conf, C_RMT, C_TLS, rmt_id);
	if (conf_bool(&tls_val)) {
		return proto == KNOTD_QUERY_PROTO_TLS;
	}

	return proto == KNOTD_QUERY_PROTO_TCP || proto == KNOTD_QUERY_PROTO_UDP;
}

static bool check_proto(knotd_query_proto_t proto, conf_val_t proto_val)
{
	unsigned mask = 0;
	switch (proto) {
	case KNOTD_QUERY_PROTO_UDP:
		mask = ACL_PROTOCOL_UDP;
		break;
	case KNOTD_QUERY_PROTO_TCP:
		mask = ACL_PROTOCOL_TCP;
		break;
	case KNOTD_QUERY_PROTO_TLS:
		mask = ACL_PROTOCOL_TLS;
		break;
	case KNOTD_QUERY_PROTO_QUIC:
		mask = ACL_PROTOCOL_QUIC;
		break;
	default:
		assert(0);
		break;
	}

	while (proto_val.code == KNOT_EOK) {
		if (conf_opt(&proto_val) & mask) {
			return true;
		}
		conf_val_next(&proto_val);
	}
	return false;
}

static bool check_addr_key(conf_t *conf, conf_val_t *addr_val, conf_val_t *key_val,
                           bool remote, const struct sockaddr_storage *addr,
                           const knot_tsig_key_t *tsig, conf_val_t *pin_val,
                           const uint8_t *session_pin, size_t session_pin_size,
                           bool deny, bool forward)
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

	/* Check if possible client certificate pin matches. */
	if (!cert_pin_check(session_pin, session_pin_size, pin_val)) {
		return false;
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
		// Empty list without key provided, forwarded DDNS, or denied.
		if (tsig->name == NULL || forward || deny) {
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
                 const knot_dname_t *zone_name, knot_pkt_t *query,
                 struct gnutls_session_int *tls_session,
                 knotd_query_proto_t proto)
{
	if (acl == NULL || addr == NULL || tsig == NULL) {
		return false;
	}

	uint8_t session_pin[KNOT_TLS_PIN_LEN];
	size_t session_pin_size = sizeof(session_pin);
	knot_tls_pin(tls_session, session_pin, &session_pin_size, false);

	bool forward = false;
	if (action == ACL_ACTION_UPDATE) {
		conf_val_t val = conf_zone_get(conf, C_MASTER, zone_name);
		if (val.code == KNOT_EOK) {
			val = conf_zone_get(conf, C_DDNS_MASTER, zone_name);
			if (val.code != KNOT_EOK || *conf_str(&val) != '\0') {
				forward = true;
			}
		}
	}

	while (acl->code == KNOT_EOK) {
		conf_val_t rmt_val = conf_id_get(conf, C_ACL, C_RMT, acl);
		bool remote = (rmt_val.code == KNOT_EOK);
		conf_val_t deny_val = conf_id_get(conf, C_ACL, C_DENY, acl);
		bool deny = conf_bool(&deny_val);

		/* Check if a remote matches given params. */
		conf_val_t addr_val, key_val, pin_val, hostname_val, cert_check_val;
		conf_mix_iter_t iter;
		conf_mix_iter_init(conf, &rmt_val, &iter);
		while (iter.id->code == KNOT_EOK) {
			addr_val = conf_id_get(conf, C_RMT, C_ADDR, iter.id);
			key_val = conf_id_get(conf, C_RMT, C_KEY, iter.id);
			pin_val = conf_id_get(conf, C_RMT, C_CERT_KEY, iter.id);
			cert_check_val = conf_id_get(conf, C_RMT, C_CERT_VALIDATE, iter.id);
			if (check_addr_key(conf, &addr_val, &key_val, remote, addr, tsig, &pin_val,
					   session_pin, session_pin_size, deny, forward)
			    && check_proto_rmt(conf, proto, iter.id)
			    && cert_check(tls_session, conf_bool(&cert_check_val) ? iter.id : NULL, true)) {
				break;
			}
			conf_mix_iter_next(&iter);
		}
		if (iter.id->code == KNOT_EOF) {
			goto next_acl;
		}
		/* Or check if acl matches given params. */
		if (!remote) {
			addr_val = conf_id_get(conf, C_ACL, C_ADDR, acl);
			key_val = conf_id_get(conf, C_ACL, C_KEY, acl);
			pin_val = conf_id_get(conf, C_ACL, C_CERT_KEY, acl);
			hostname_val = conf_id_get(conf, C_ACL, C_TLS_HOSTNAME, acl);
			cert_check_val = conf_id_get(conf, C_ACL, C_CERT_VALIDATE, acl);
			if (!check_addr_key(conf, &addr_val, &key_val, remote, addr, tsig, &pin_val,
					    session_pin, session_pin_size, deny, forward)
			    || !cert_check(tls_session, conf_bool(&cert_check_val) ? &hostname_val : NULL, false)) {
				goto next_acl;
			}

			/* Check protocol match */
			conf_val_t proto_val = conf_id_get(conf, C_ACL, C_PROTOCOL, acl);
			if (proto_val.code == KNOT_EOK && !check_proto(proto, proto_val)) {
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
		if (tsig->name != NULL && key_val.code == KNOT_EOK) {
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
                 knot_tsig_key_t *tsig, struct gnutls_session_int *tls_session,
                 knotd_query_proto_t proto)
{
	if (!conf->cache.srv_auto_acl) {
		return false;
	}

	uint8_t session_pin[KNOT_TLS_PIN_LEN];
	size_t session_pin_size = sizeof(session_pin);
	knot_tls_pin(tls_session, session_pin, &session_pin_size, false);

	conf_mix_iter_t iter;
	conf_mix_iter_init(conf, rmts, &iter);
	while (iter.id->code == KNOT_EOK) {
		conf_val_t val = conf_id_get(conf, C_RMT, C_AUTO_ACL, iter.id);
		if (!conf_bool(&val)) {
			goto next_remote;
		}

		if (!check_proto_rmt(conf, proto, iter.id)) {
			goto next_remote;
		}

		conf_val_t pin_val = conf_id_get(conf, C_RMT, C_CERT_KEY, iter.id);
		if (!cert_pin_check(session_pin, session_pin_size, &pin_val)) {
			goto next_remote;
		}

		val = conf_id_get(conf, C_RMT, C_CERT_VALIDATE, iter.id);
		if (!cert_check(tls_session, conf_bool(&val) ? iter.id : NULL, true)) {
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
