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

#pragma once

#include "libknot/lookup.h"
#include "libknot/yparser/ypschema.h"

#define C_ACL			"\x03""acl"
#define C_ACTION		"\x06""action"
#define C_ADDR			"\x07""address"
#define C_ADJUST_THR		"\x0E""adjust-threads"
#define C_ALG			"\x09""algorithm"
#define C_ANS_ROTATION		"\x0F""answer-rotation"
#define C_ANY			"\x03""any"
#define C_APPEND		"\x06""append"
#define C_ASYNC_START		"\x0B""async-start"
#define C_AUTO_ACL		"\x0D""automatic-acl"
#define C_BACKEND		"\x07""backend"
#define C_BG_WORKERS		"\x12""background-workers"
#define C_BLOCK_NOTIFY_XFR	"\x1B""block-notify-after-transfer"
#define C_CATALOG_DB		"\x0A""catalog-db"
#define C_CATALOG_DB_MAX_SIZE	"\x13""catalog-db-max-size"
#define C_CATALOG_GROUP		"\x0D""catalog-group"
#define C_CATALOG_ROLE		"\x0C""catalog-role"
#define C_CATALOG_TPL		"\x10""catalog-template"
#define C_CATALOG_ZONE		"\x0C""catalog-zone"
#define C_CDS_CDNSKEY		"\x13""cds-cdnskey-publish"
#define C_CDS_DIGESTTYPE	"\x0F""cds-digest-type"
#define C_CERT_FILE		"\x09""cert-file"
#define C_CHK_INTERVAL		"\x0E""check-interval"
#define C_COMMENT		"\x07""comment"
#define C_CONFIG		"\x06""config"
#define C_CTL			"\x07""control"
#define C_DB			"\x08""database"
#define C_DBUS_EVENT		"\x0A""dbus-event"
#define C_DDNS_MASTER		"\x0B""ddns-master"
#define C_DENY			"\x04""deny"
#define C_DNSKEY_MGMT		"\x11""dnskey-management"
#define C_DNSKEY_TTL		"\x0A""dnskey-ttl"
#define C_DNSSEC_POLICY		"\x0D""dnssec-policy"
#define C_DNSSEC_SIGNING	"\x0E""dnssec-signing"
#define C_DNSSEC_VALIDATION	"\x11""dnssec-validation"
#define C_DOMAIN		"\x06""domain"
#define C_DS_PUSH		"\x07""ds-push"
#define C_ECS			"\x12""edns-client-subnet"
#define C_EXPIRE_MAX_INTERVAL	"\x13""expire-max-interval"
#define C_EXPIRE_MIN_INTERVAL	"\x13""expire-min-interval"
#define C_FILE			"\x04""file"
#define C_GLOBAL_MODULE		"\x0D""global-module"
#define C_ID			"\x02""id"
#define C_IDENT			"\x08""identity"
#define C_INCL			"\x07""include"
#define C_JOURNAL_CONTENT	"\x0F""journal-content"
#define C_JOURNAL_DB		"\x0A""journal-db"
#define C_JOURNAL_DB_MAX_SIZE	"\x13""journal-db-max-size"
#define C_JOURNAL_DB_MODE	"\x0F""journal-db-mode"
#define C_JOURNAL_MAX_DEPTH	"\x11""journal-max-depth"
#define C_JOURNAL_MAX_USAGE	"\x11""journal-max-usage"
#define C_KASP_DB		"\x07""kasp-db"
#define C_KASP_DB_MAX_SIZE	"\x10""kasp-db-max-size"
#define C_DELETE_DELAY		"\x0C""delete-delay"
#define C_KEY			"\x03""key"
#define C_KEYSTORE		"\x08""keystore"
#define C_KEY_FILE		"\x08""key-file"
#define C_KEY_LABEL		"\x09""key-label"
#define C_KSK_LIFETIME		"\x0C""ksk-lifetime"
#define C_KSK_SBM		"\x0E""ksk-submission"
#define C_KSK_SHARED		"\x0a""ksk-shared"
#define C_KSK_SIZE		"\x08""ksk-size"
#define C_LISTEN		"\x06""listen"
#define C_LOG			"\x03""log"
#define C_MANUAL		"\x06""manual"
#define C_MASTER		"\x06""master"
#define C_MODULE		"\x06""module"
#define C_NO_EDNS		"\x07""no-edns"
#define C_NOTIFY		"\x06""notify"
#define C_NSEC3			"\x05""nsec3"
#define C_NSEC3_ITER		"\x10""nsec3-iterations"
#define C_NSEC3_OPT_OUT		"\x0D""nsec3-opt-out"
#define C_NSEC3_SALT_LEN	"\x11""nsec3-salt-length"
#define C_NSEC3_SALT_LIFETIME	"\x13""nsec3-salt-lifetime"
#define C_NSID			"\x04""nsid"
#define C_OFFLINE_KSK		"\x0B""offline-ksk"
#define C_PARENT		"\x06""parent"
#define C_PARENT_DELAY		"\x0C""parent-delay"
#define C_PIDFILE		"\x07""pidfile"
#define C_POLICY		"\x06""policy"
#define C_PROPAG_DELAY		"\x11""propagation-delay"
#define C_PROXY_ALLOWLIST	"\x0F""proxy-allowlist"
#define C_QUIC			"\x04""quic"
#define C_QUIC_IDLE_CLOSE	"\x17""quic-idle-close-timeout"
#define C_QUIC_LOG		"\x08""quic-log"
#define C_QUIC_MAX_CLIENTS	"\x10""quic-max-clients"
#define C_QUIC_OUTBUF_MAX_SIZE	"\x14""quic-outbuf-max-size"
#define C_QUIC_PORT		"\x09""quic-port"
#define C_REFRESH_MAX_INTERVAL	"\x14""refresh-max-interval"
#define C_REFRESH_MIN_INTERVAL	"\x14""refresh-min-interval"
#define C_REPRO_SIGNING		"\x14""reproducible-signing"
#define C_RETRY_MAX_INTERVAL	"\x12""retry-max-interval"
#define C_RETRY_MIN_INTERVAL	"\x12""retry-min-interval"
#define C_RMT			"\x06""remote"
#define C_RMTS			"\x07""remotes"
#define C_RMT_POOL_LIMIT	"\x11""remote-pool-limit"
#define C_RMT_POOL_TIMEOUT	"\x13""remote-pool-timeout"
#define C_RMT_RETRY_DELAY	"\x12""remote-retry-delay"
#define C_ROUTE_CHECK		"\x0B""route-check"
#define C_RRSIG_LIFETIME	"\x0E""rrsig-lifetime"
#define C_RRSIG_PREREFRESH	"\x11""rrsig-pre-refresh"
#define C_RRSIG_REFRESH		"\x0D""rrsig-refresh"
#define C_RUNDIR		"\x06""rundir"
#define C_SBM			"\x0A""submission"
#define C_SECRET		"\x06""secret"
#define C_SEM_CHECKS		"\x0F""semantic-checks"
#define C_SERIAL_POLICY		"\x0D""serial-policy"
#define C_SERVER		"\x06""server"
#define C_SIGNING_THREADS	"\x0F""signing-threads"
#define C_SINGLE_TYPE_SIGNING	"\x13""single-type-signing"
#define C_SOCKET_AFFINITY	"\x0F""socket-affinity"
#define C_SRV			"\x06""server"
#define C_STATS			"\x0A""statistics"
#define C_STORAGE		"\x07""storage"
#define C_TARGET		"\x06""target"
#define C_TCP			"\x03""tcp"
#define C_TCP_FASTOPEN		"\x0C""tcp-fastopen"
#define C_TCP_IDLE_CLOSE	"\x16""tcp-idle-close-timeout"
#define C_TCP_IDLE_RESET	"\x16""tcp-idle-reset-timeout"
#define C_TCP_IDLE_TIMEOUT	"\x10""tcp-idle-timeout"
#define C_TCP_INBUF_MAX_SIZE	"\x12""tcp-inbuf-max-size"
#define C_TCP_IO_TIMEOUT	"\x0E""tcp-io-timeout"
#define C_TCP_MAX_CLIENTS	"\x0F""tcp-max-clients"
#define C_TCP_OUTBUF_MAX_SIZE	"\x13""tcp-outbuf-max-size"
#define C_TCP_RESEND		"\x12""tcp-resend-timeout"
#define C_TCP_REUSEPORT		"\x0D""tcp-reuseport"
#define C_TCP_RMT_IO_TIMEOUT	"\x15""tcp-remote-io-timeout"
#define C_TCP_WORKERS		"\x0B""tcp-workers"
#define C_TIMEOUT		"\x07""timeout"
#define C_TIMER			"\x05""timer"
#define C_TIMER_DB		"\x08""timer-db"
#define C_TIMER_DB_MAX_SIZE	"\x11""timer-db-max-size"
#define C_TPL			"\x08""template"
#define C_UDP			"\x03""udp"
#define C_UDP_MAX_PAYLOAD	"\x0F""udp-max-payload"
#define C_UDP_MAX_PAYLOAD_IPV4	"\x14""udp-max-payload-ipv4"
#define C_UDP_MAX_PAYLOAD_IPV6	"\x14""udp-max-payload-ipv6"
#define C_UDP_WORKERS		"\x0B""udp-workers"
#define C_UNSAFE_OPERATION	"\x10""unsafe-operation"
#define C_UPDATE_OWNER		"\x0C""update-owner"
#define C_UPDATE_OWNER_MATCH	"\x12""update-owner-match"
#define C_UPDATE_OWNER_NAME	"\x11""update-owner-name"
#define C_UPDATE_TYPE		"\x0B""update-type"
#define C_USER			"\x04""user"
#define C_VERSION		"\x07""version"
#define C_VIA			"\x03""via"
#define C_XDP			"\x03""xdp"
#define C_ZONE			"\x04""zone"
#define C_ZONEFILE_LOAD		"\x0D""zonefile-load"
#define C_ZONEFILE_SYNC		"\x0D""zonefile-sync"
#define C_ZONEMD_GENERATE	"\x0F""zonemd-generate"
#define C_ZONEMD_VERIFY		"\x0D""zonemd-verify"
#define C_ZONE_MAX_SIZE		"\x0D""zone-max-size"
#define C_ZONE_MAX_TTL		"\x0C""zone-max-ttl"
#define C_ZSK_LIFETIME		"\x0C""zsk-lifetime"
#define C_ZSK_SIZE		"\x08""zsk-size"

// Legacy items.
#define C_DISABLE_ANY		"\x0B""disable-any"
#define C_LISTEN_XDP		"\x0A""listen-xdp"
#define C_MAX_TIMER_DB_SIZE	"\x11""max-timer-db-size"
#define C_MAX_JOURNAL_DB_SIZE	"\x13""max-journal-db-size"
#define C_MAX_KASP_DB_SIZE	"\x10""max-kasp-db-size"
#define C_TCP_HSHAKE_TIMEOUT	"\x15""tcp-handshake-timeout"
#define C_TCP_REPLY_TIMEOUT	"\x11""tcp-reply-timeout"
#define C_MAX_TCP_CLIENTS	"\x0F""max-tcp-clients"
#define C_MAX_UDP_PAYLOAD	"\x0F""max-udp-payload"
#define C_MAX_IPV4_UDP_PAYLOAD	"\x14""max-ipv4-udp-payload"
#define C_MAX_IPV6_UDP_PAYLOAD	"\x14""max-ipv6-udp-payload"
#define C_MAX_ZONE_SIZE		"\x0D""max-zone-size"
#define C_MAX_REFRESH_INTERVAL	"\x14""max-refresh-interval"
#define C_MIN_REFRESH_INTERVAL	"\x14""min-refresh-interval"
#define C_MAX_JOURNAL_DEPTH	"\x11""max-journal-depth"
#define C_MAX_JOURNAL_USAGE	"\x11""max-journal-usage"

enum {
	KEYSTORE_BACKEND_PEM    = 1,
	KEYSTORE_BACKEND_PKCS11 = 2,
};

enum {
	UNSAFE_NONE       =  0,
	UNSAFE_KEYSET     = (1 << 0),
	UNSAFE_DNSKEY     = (1 << 1),
	UNSAFE_NSEC       = (1 << 2),
	UNSAFE_EXPIRED    = (1 << 3),
};

enum {
	CDS_CDNSKEY_NONE      = 0,
	CDS_CDNSKEY_EMPTY     = 1,
	CDS_CDNSKEY_ROLLOVER  = 2,
	CDS_CDNSKEY_ALWAYS    = 3,
	CDS_CDNSKEY_DOUBLE_DS = 4,
};

enum {
	DNSKEY_MGMT_FULL        = 0,
	DNSKEY_MGMT_INCREMENTAL = 1,
};

enum {
	SERIAL_POLICY_INCREMENT  = 1,
	SERIAL_POLICY_UNIXTIME   = 2,
	SERIAL_POLICY_DATESERIAL = 3,
};

enum {
	SEMCHECKS_OFF  = 0,
	SEMCHECKS_ON   = 1,
	SEMCHECKS_SOFT = 2,
};

enum {
	ZONE_DIGEST_NONE   = 0,
	ZONE_DIGEST_SHA384 = 1,
	ZONE_DIGEST_SHA512 = 2,
	ZONE_DIGEST_REMOVE = 255,
};

enum {
	JOURNAL_CONTENT_NONE    = 0,
	JOURNAL_CONTENT_CHANGES = 1,
	JOURNAL_CONTENT_ALL     = 2,
};

enum {
	JOURNAL_MODE_ROBUST = 0, // Robust journal DB disk synchronization.
	JOURNAL_MODE_ASYNC  = 1, // Asynchronous journal DB disk synchronization.
};

enum {
	ZONEFILE_LOAD_NONE  = 0,
	ZONEFILE_LOAD_DIFF  = 1,
	ZONEFILE_LOAD_WHOLE = 2,
	ZONEFILE_LOAD_DIFSE = 3,
};

enum {
	CATALOG_ROLE_NONE      = 0,
	CATALOG_ROLE_INTERPRET = 1,
	CATALOG_ROLE_GENERATE  = 2,
	CATALOG_ROLE_MEMBER    = 3,
};

enum {
	DBUS_EVENT_NONE            = 0,
	DBUS_EVENT_RUNNING         = (1 << 0),
	DBUS_EVENT_ZONE_UPDATED    = (1 << 1),
	DBUS_EVENT_ZONE_SUBMISSION = (1 << 2),
	DBUS_EVENT_ZONE_INVALID    = (1 << 3),
};

extern const knot_lookup_t acl_actions[];

extern const yp_item_t conf_schema[];
