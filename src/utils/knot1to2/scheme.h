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

#pragma once

typedef enum {
	S_FIRST = 0,
	S_SRV = S_FIRST,
	S_KEY,
	S_RMT,
	S_ACL,
	S_CTL,
	S_DNSTAP,
	S_SYNTH,
	S_DNSPROXY,
	S_ROSEDB,
	S_TPL,
	S_ZONE,
	S_LOG,
	S_LAST = S_LOG
} section_t;

typedef enum {
	R_SYS,      // -> SERVER
	R_IF,       // -> SERVER
	R_KEY,      // -> KEY
	R_RMT,      // -> REMOTE
	R_RMT_ACL,  // -> ACL
	R_CTL,      // -> CONTROL
	R_ZONEM1,   // -> MOD_DNSTAP
	R_ZONEM2,   // -> MOD_SYNTRECORD
	R_ZONEM3,   // -> MOD_DNSPROXY
	R_ZONEM4,   // -> MOD_ROSEDB
	R_ZONE_TPL, // -> TEMPLATE default
	R_ZONE,     // -> ZONE
	R_LOG,      // -> LOG
} run_t;

#define C_ACL			"\x03""acl"
#define C_ACTION		"\x06""action"
#define C_ADDR			"\x07""address"
#define C_ALG			"\x09""algorithm"
#define C_ANY			"\x03""any"
#define C_ASYNC_START		"\x0B""async-start"
#define C_BG_WORKERS		"\x12""background-workers"
#define C_COMMENT		"\x07""comment"
#define C_CTL			"\x07""control"
#define C_DENY			"\x04""deny"
#define C_DISABLE_ANY		"\x0B""disable-any"
#define C_DNSSEC_SIGNING	"\x0E""dnssec-signing"
#define C_DOMAIN		"\x06""domain"
#define C_FILE			"\x04""file"
#define C_ID			"\x02""id"
#define C_IDENT			"\x08""identity"
#define C_INCL			"\x07""include"
#define C_IXFR_DIFF		"\x15""ixfr-from-differences"
#define C_KASP_DB		"\x07""kasp-db"
#define C_KEY			"\x03""key"
#define C_LISTEN		"\x06""listen"
#define C_LOG			"\x03""log"
#define C_MASTER		"\x06""master"
#define C_MAX_JOURNAL_SIZE	"\x10""max-journal-size"
#define C_MAX_TCP_CLIENTS	"\x0F""max-tcp-clients"
#define C_MAX_UDP_PAYLOAD	"\x0F""max-udp-payload"
#define C_MODULE		"\x06""module"
#define C_NOTIFY		"\x06""notify"
#define C_NSID			"\x04""nsid"
#define C_PIDFILE		"\x07""pidfile"
#define C_RATE_LIMIT		"\x0A""rate-limit"
#define C_RATE_LIMIT_SLIP	"\x0F""rate-limit-slip"
#define C_RATE_LIMIT_TBL_SIZE	"\x15""rate-limit-table-size"
#define C_RMT			"\x06""remote"
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
#define C_TIMER_DB		"\x08""timer-db"
#define C_TPL			"\x08""template"
#define C_UDP_WORKERS		"\x0B""udp-workers"
#define C_USER			"\x04""user"
#define C_VERSION		"\x07""version"
#define C_VIA			"\x03""via"
#define C_ZONE			"\x04""zone"
#define C_ZONEFILE_SYNC		"\x0D""zonefile-sync"

#define C_MOD_DNSPROXY		"\x0C""mod-dnsproxy"
#define C_MOD_DNSTAP		"\x0A""mod-dnstap"
#define C_MOD_ROSEDB		"\x0A""mod-rosedb"
#define C_MOD_SYNTH_RECORD	"\x10""mod-synth-record"

inline static const char* section_name(section_t id)
{
	switch (id) {
	case S_SRV:		return C_SRV;
	case S_KEY:		return C_KEY;
	case S_ACL:		return C_ACL;
	case S_RMT:		return C_RMT;
	case S_CTL:		return C_CTL;
	case S_DNSTAP:		return C_MOD_DNSTAP;
	case S_SYNTH:		return C_MOD_SYNTH_RECORD;
	case S_DNSPROXY:	return C_MOD_DNSPROXY;
	case S_ROSEDB:		return C_MOD_ROSEDB;
	case S_TPL:		return C_TPL;
	case S_ZONE:		return C_ZONE;
	case S_LOG:		return C_LOG;
	default:		return NULL;
	}
}
