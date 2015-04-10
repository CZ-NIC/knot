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

#include "libknot/yparser/ypscheme.h"

#define C_ACL			"\x03""acl"
#define C_ACTION		"\x06""action"
#define C_ADDR			"\x07""address"
#define C_ALG			"\x09""algorithm"
#define C_ANY			"\x03""any"
#define C_ASYNC_START		"\x12""asynchronous-start"
#define C_BG_WORKERS		"\x12""background-workers"
#define C_COMMENT		"\x07""comment"
#define C_CTL			"\x07""control"
#define C_DISABLE_ANY		"\x0B""disable-any"
#define C_DOMAIN		"\x06""domain"
#define C_DNSSEC_ENABLE		"\x0D""dnssec-enable"
#define C_DNSSEC_KEYDIR		"\x0D""dnssec-keydir"
#define C_FILE			"\x04""file"
#define C_IDENT			"\x08""identity"
#define C_ID			"\x02""id"
#define C_INCL			"\x07""include"
#define C_IXFR_DIFF		"\x15""ixfr-from-differences"
#define C_IXFR_FSLIMIT		"\x0C""ixfr-fslimit"
#define C_KEY			"\x03""key"
#define C_LOG			"\x03""log"
#define C_LISTEN		"\x06""listen"
#define C_MASTER		"\x06""master"
#define C_MAX_CONN_HANDSHAKE	"\x12""max-conn-handshake"
#define C_MAX_CONN_IDLE		"\x0D""max-conn-idle"
#define C_MAX_CONN_REPLY	"\x0E""max-conn-reply"
#define C_MAX_TCP_CLIENTS	"\x0F""max-tcp-clients"
#define C_MAX_UDP_PAYLOAD	"\x0F""max-udp-payload"
#define C_MODULE		"\x06""module"
#define C_NOTIFY		"\x06""notify"
#define C_NOTIFY_RETRIES	"\x0E""notify-retries"
#define C_NOTIFY_TIMEOUT	"\x0E""notify-timeout"
#define C_NSID			"\x04""nsid"
#define C_PIDFILE		"\x07""pidfile"
#define C_RATE_LIMIT		"\x0A""rate-limit"
#define C_RATE_LIMIT_SIZE	"\x0F""rate-limit-size"
#define C_RATE_LIMIT_SLIP	"\x0F""rate-limit-slip"
#define C_RMT			"\x06""remote"
#define C_RUNDIR		"\x06""rundir"
#define C_SECRET		"\x06""secret"
#define C_SEM_CHECKS		"\x0F""semantic-checks"
#define C_SERIAL_POLICY		"\x0D""serial-policy"
#define C_SERVER		"\x06""server"
#define C_SIG_LIFETIME		"\x12""signature-lifetime"
#define C_STORAGE		"\x07""storage"
#define C_SRV			"\x06""server"
#define C_TO			"\x02""to"
#define C_TPL			"\x08""template"
#define C_TRANSFERS		"\x09""transfers"
#define C_USER			"\x04""user"
#define C_VERSION		"\x07""version"
#define C_VIA			"\x03""via"
#define C_WORKERS		"\x07""workers"
#define C_ZONE			"\x04""zone"
#define C_ZONEFILE_SYNC		"\x0D""zonefile-sync"

enum {
	SERIAL_POLICY_INCREMENT = 1,
	SERIAL_POLICY_UNIXTIME  = 2
};

extern const yp_item_t conf_scheme[];
