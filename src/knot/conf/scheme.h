/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * Server configuration scheme.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include "libknot/lookup.h"
#include "libknot/yparser/ypscheme.h"

#define C_ACL			"\x03""acl"
#define C_ACTION		"\x06""action"
#define C_ADDR			"\x07""address"
#define C_ALG			"\x09""algorithm"
#define C_ANY			"\x03""any"
#define C_ASYNC_START		"\x0B""async-start"
#define C_BACKEND		"\x07""backend"
#define C_BG_WORKERS		"\x12""background-workers"
#define C_COMMENT		"\x07""comment"
#define C_CONFIG		"\x06""config"
#define C_CTL			"\x07""control"
#define C_DDNS_MASTER		"\x0B""ddns-master"
#define C_DENY			"\x04""deny"
#define C_DISABLE_ANY		"\x0B""disable-any"
#define C_DNSKEY_TTL		"\x0A""dnskey-ttl"
#define C_DNSSEC_POLICY		"\x0D""dnssec-policy"
#define C_DNSSEC_SIGNING	"\x0E""dnssec-signing"
#define C_DOMAIN		"\x06""domain"
#define C_FILE			"\x04""file"
#define C_GLOBAL_MODULE		"\x0D""global-module"
#define C_ID			"\x02""id"
#define C_IDENT			"\x08""identity"
#define C_INCL			"\x07""include"
#define C_IXFR_DIFF		"\x15""ixfr-from-differences"
#define C_JOURNAL		"\x07""journal"
#define C_KASP_DB		"\x07""kasp-db"
#define C_KEY			"\x03""key"
#define C_KEYSTORE		"\x08""keystore"
#define C_KSK_SIZE		"\x08""ksk-size"
#define C_LISTEN		"\x06""listen"
#define C_LOG			"\x03""log"
#define C_MANUAL		"\x06""manual"
#define C_MASTER		"\x06""master"
#define C_MAX_JOURNAL_SIZE	"\x10""max-journal-size"
#define C_MAX_TCP_CLIENTS	"\x0F""max-tcp-clients"
#define C_MAX_UDP_PAYLOAD	"\x0F""max-udp-payload"
#define C_MAX_ZONE_SIZE		"\x0D""max-zone-size"
#define C_MAX_IPV4_UDP_PAYLOAD	"\x14""max-ipv4-udp-payload"
#define C_MAX_IPV6_UDP_PAYLOAD	"\x14""max-ipv6-udp-payload"
#define C_MODULE		"\x06""module"
#define C_NOTIFY		"\x06""notify"
#define C_NSEC3			"\x05""nsec3"
#define C_NSEC3_ITER		"\x10""nsec3-iterations"
#define C_NSEC3_SALT_LEN	"\x11""nsec3-salt-length"
#define C_NSEC3_SALT_LIFETIME	"\x13""nsec3-salt-lifetime"
#define C_NSID			"\x04""nsid"
#define C_PIDFILE		"\x07""pidfile"
#define C_POLICY		"\x06""policy"
#define C_PROPAG_DELAY		"\x11""propagation-delay"
#define C_RATE_LIMIT		"\x0A""rate-limit"
#define C_RATE_LIMIT_SLIP	"\x0F""rate-limit-slip"
#define C_RATE_LIMIT_TBL_SIZE	"\x15""rate-limit-table-size"
#define C_RATE_LIMIT_WHITELIST	"\x14""rate-limit-whitelist"
#define C_REQUEST_EDNS_OPTION	"\x13""request-edns-option"
#define C_RMT			"\x06""remote"
#define C_RRSIG_LIFETIME	"\x0E""rrsig-lifetime"
#define C_RRSIG_REFRESH		"\x0D""rrsig-refresh"
#define C_RUNDIR		"\x06""rundir"
#define C_SECRET		"\x06""secret"
#define C_SEM_CHECKS		"\x0F""semantic-checks"
#define C_SERIAL_POLICY		"\x0D""serial-policy"
#define C_SERVER		"\x06""server"
#define C_SRV			"\x06""server"
#define C_STORAGE		"\x07""storage"
#define C_TARGET		"\x06""target"
#define C_TCP_HSHAKE_TIMEOUT	"\x15""tcp-handshake-timeout"
#define C_TCP_IDLE_TIMEOUT	"\x10""tcp-idle-timeout"
#define C_TCP_REPLY_TIMEOUT	"\x11""tcp-reply-timeout"
#define C_TCP_WORKERS		"\x0B""tcp-workers"
#define C_TIMEOUT		"\x07""timeout"
#define C_TIMER_DB		"\x08""timer-db"
#define C_TPL			"\x08""template"
#define C_UDP_WORKERS		"\x0B""udp-workers"
#define C_USER			"\x04""user"
#define C_VERSION		"\x07""version"
#define C_VIA			"\x03""via"
#define C_ZONE			"\x04""zone"
#define C_ZONEFILE_SYNC		"\x0D""zonefile-sync"
#define C_ZSK_LIFETIME		"\x0C""zsk-lifetime"
#define C_ZSK_SIZE		"\x08""zsk-size"

enum {
	KEYSTORE_BACKEND_PEM    = 1,
	KEYSTORE_BACKEND_PKCS11 = 2
};

enum {
	SERIAL_POLICY_INCREMENT = 1,
	SERIAL_POLICY_UNIXTIME  = 2
};

extern const knot_lookup_t acl_actions[];

extern const yp_item_t conf_scheme[];

/*! @} */
