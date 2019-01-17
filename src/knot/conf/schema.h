/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "libknot/lookup.h"
#include "libknot/yparser/ypschema.h"

#define C_ACL			"\x03""acl"
#define C_ACTION		"\x06""action"
#define C_ADDR			"\x07""address"
#define C_ALG			"\x09""algorithm"
#define C_ANS_ROTATION		"\x0F""answer-rotation"
#define C_ANY			"\x03""any"
#define C_APPEND		"\x06""append"
#define C_ASYNC_START		"\x0B""async-start"
#define C_BACKEND		"\x07""backend"
#define C_BG_WORKERS		"\x12""background-workers"
#define C_CHILD_RECORDS		"\x13""cds-cdnskey-publish"
#define C_CHK_INTERVAL		"\x0E""check-interval"
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
#define C_DS_PUSH		"\x07""ds-push"
#define C_ECS			"\x12""edns-client-subnet"
#define C_FILE			"\x04""file"
#define C_GLOBAL_MODULE		"\x0D""global-module"
#define C_ID			"\x02""id"
#define C_IDENT			"\x08""identity"
#define C_INCL			"\x07""include"
#define C_JOURNAL_CONTENT	"\x0F""journal-content"
#define C_JOURNAL_DB		"\x0A""journal-db"
#define C_JOURNAL_DB_MODE	"\x0F""journal-db-mode"
#define C_KASP_DB		"\x07""kasp-db"
#define C_KEY			"\x03""key"
#define C_KEYSTORE		"\x08""keystore"
#define C_KSK_LIFETIME		"\x0C""ksk-lifetime"
#define C_KSK_SBM		"\x0E""ksk-submission"
#define C_KSK_SHARED		"\x0a""ksk-shared"
#define C_KSK_SIZE		"\x08""ksk-size"
#define C_LISTEN		"\x06""listen"
#define C_LOG			"\x03""log"
#define C_MANUAL		"\x06""manual"
#define C_MASTER		"\x06""master"
#define C_MAX_IPV4_UDP_PAYLOAD	"\x14""max-ipv4-udp-payload"
#define C_MAX_IPV6_UDP_PAYLOAD	"\x14""max-ipv6-udp-payload"
#define C_MAX_JOURNAL_DB_SIZE	"\x13""max-journal-db-size"
#define C_MAX_JOURNAL_DEPTH	"\x11""max-journal-depth"
#define C_MAX_JOURNAL_USAGE	"\x11""max-journal-usage"
#define C_MAX_KASP_DB_SIZE	"\x10""max-kasp-db-size"
#define C_MAX_REFRESH_INTERVAL	"\x14""max-refresh-interval"
#define C_MAX_TCP_CLIENTS	"\x0F""max-tcp-clients"
#define C_MAX_TIMER_DB_SIZE	"\x11""max-timer-db-size"
#define C_MAX_UDP_PAYLOAD	"\x0F""max-udp-payload"
#define C_MAX_ZONE_SIZE		"\x0D""max-zone-size"
#define C_MIN_REFRESH_INTERVAL	"\x14""min-refresh-interval"
#define C_MODULE		"\x06""module"
#define C_NOTIFY		"\x06""notify"
#define C_NSEC3			"\x05""nsec3"
#define C_NSEC3_ITER		"\x10""nsec3-iterations"
#define C_NSEC3_OPT_OUT		"\x0D""nsec3-opt-out"
#define C_NSEC3_SALT_LEN	"\x11""nsec3-salt-length"
#define C_NSEC3_SALT_LIFETIME	"\x13""nsec3-salt-lifetime"
#define C_NSID			"\x04""nsid"
#define C_OFFLINE_KSK		"\x0B""offline-ksk"
#define C_PARENT		"\x06""parent"
#define C_PIDFILE		"\x07""pidfile"
#define C_POLICY		"\x06""policy"
#define C_PROPAG_DELAY		"\x11""propagation-delay"
#define C_REQUEST_EDNS_OPTION	"\x13""request-edns-option"
#define C_RMT			"\x06""remote"
#define C_RRSIG_LIFETIME	"\x0E""rrsig-lifetime"
#define C_RRSIG_REFRESH		"\x0D""rrsig-refresh"
#define C_RUNDIR		"\x06""rundir"
#define C_SBM			"\x0A""submission"
#define C_SECRET		"\x06""secret"
#define C_SEM_CHECKS		"\x0F""semantic-checks"
#define C_SERIAL_POLICY		"\x0D""serial-policy"
#define C_SERVER		"\x06""server"
#define C_SIGNING_THREADS	"\x0F""signing-threads"
#define C_SINGLE_TYPE_SIGNING	"\x13""single-type-signing"
#define C_SRV			"\x06""server"
#define C_STATS			"\x0A""statistics"
#define C_STORAGE		"\x07""storage"
#define C_TARGET		"\x06""target"
#define C_TCP_HSHAKE_TIMEOUT	"\x15""tcp-handshake-timeout"
#define C_TCP_IDLE_TIMEOUT	"\x10""tcp-idle-timeout"
#define C_TCP_REPLY_TIMEOUT	"\x11""tcp-reply-timeout"
#define C_TCP_WORKERS		"\x0B""tcp-workers"
#define C_TIMEOUT		"\x07""timeout"
#define C_TIMER			"\x05""timer"
#define C_TIMER_DB		"\x08""timer-db"
#define C_TPL			"\x08""template"
#define C_UDP_WORKERS		"\x0B""udp-workers"
#define C_UPDATE_OWNER		"\x0C""update-owner"
#define C_UPDATE_OWNER_MATCH	"\x12""update-owner-match"
#define C_UPDATE_OWNER_NAME	"\x11""update-owner-name"
#define C_UPDATE_TYPE		"\x0B""update-type"
#define C_USER			"\x04""user"
#define C_VERSION		"\x07""version"
#define C_VIA			"\x03""via"
#define C_ZONE			"\x04""zone"
#define C_ZONEFILE_LOAD		"\x0D""zonefile-load"
#define C_ZONEFILE_SYNC		"\x0D""zonefile-sync"
#define C_ZONE_MAX_TLL		"\x0C""zone-max-ttl"
#define C_ZSK_LIFETIME		"\x0C""zsk-lifetime"
#define C_ZSK_SIZE		"\x08""zsk-size"

enum {
	KEYSTORE_BACKEND_PEM    = 1,
	KEYSTORE_BACKEND_PKCS11 = 2,
};

enum {
	CHILD_RECORDS_NONE     = 0,
	CHILD_RECORDS_EMPTY    = 1,
	CHILD_RECORDS_ROLLOVER = 2,
	CHILD_RECORDS_ALWAYS   = 3,
	CHILD_RECORDS_DOUBLE_DS= 4,
};

enum {
	SERIAL_POLICY_INCREMENT  = 1,
	SERIAL_POLICY_UNIXTIME   = 2,
	SERIAL_POLICY_DATESERIAL = 3,
};

enum {
	JOURNAL_CONTENT_NONE    = 0,
	JOURNAL_CONTENT_CHANGES = 1,
	JOURNAL_CONTENT_ALL     = 2,
};

enum {
	ZONEFILE_LOAD_NONE  = 0,
	ZONEFILE_LOAD_DIFF  = 1,
	ZONEFILE_LOAD_WHOLE = 2,
	ZONEFILE_LOAD_DIFSE = 3,
};

extern const knot_lookup_t acl_actions[];

extern const yp_item_t conf_schema[];
