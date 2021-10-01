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

#include "libknot/libknot.h"
#include "knot/server/server.h"

#define CTL_FLAG_FORCE		"F"
#define CTL_FLAG_BLOCKING	"B"
#define CTL_FLAG_ADD		"+"
#define CTL_FLAG_REM		"-"

#define CTL_FLAG_LIST_SCHEMA	"s"
#define CTL_FLAG_LIST_TXN	"t"
#define CTL_FLAG_LIST_ZONES	"z"

#define CTL_FILTER_FLUSH_OUTDIR		'd'

#define CTL_FILTER_STATUS_ROLE		'r'
#define CTL_FILTER_STATUS_SERIAL	's'
#define CTL_FILTER_STATUS_TRANSACTION	't'
#define CTL_FILTER_STATUS_FREEZE	'f'
#define CTL_FILTER_STATUS_CATALOG	'c'
#define CTL_FILTER_STATUS_EVENTS	'e'

#define CTL_FILTER_PURGE_EXPIRE		'e'
#define CTL_FILTER_PURGE_ZONEFILE	'f'
#define CTL_FILTER_PURGE_JOURNAL	'j'
#define CTL_FILTER_PURGE_TIMERS		't'
#define CTL_FILTER_PURGE_KASPDB		'k'
#define CTL_FILTER_PURGE_CATALOG	'c'
#define CTL_FILTER_PURGE_ORPHAN		'o'

#define CTL_FILTER_BACKUP_OUTDIR	'd'
#define CTL_FILTER_BACKUP_ZONEFILE	'z'
#define CTL_FILTER_BACKUP_NOZONEFILE	'Z'
#define CTL_FILTER_BACKUP_JOURNAL	'j'
#define CTL_FILTER_BACKUP_NOJOURNAL	'J'
#define CTL_FILTER_BACKUP_TIMERS	't'
#define CTL_FILTER_BACKUP_NOTIMERS	'T'
#define CTL_FILTER_BACKUP_KASPDB	'k'
#define CTL_FILTER_BACKUP_NOKASPDB	'K'
#define CTL_FILTER_BACKUP_CATALOG	'c'
#define CTL_FILTER_BACKUP_NOCATALOG	'C'

/*! Control commands. */
typedef enum {
	CTL_NONE,

	CTL_STATUS,
	CTL_STOP,
	CTL_RELOAD,
	CTL_STATS,

	CTL_ZONE_STATUS,
	CTL_ZONE_RELOAD,
	CTL_ZONE_REFRESH,
	CTL_ZONE_RETRANSFER,
	CTL_ZONE_NOTIFY,
	CTL_ZONE_FLUSH,
	CTL_ZONE_BACKUP,
	CTL_ZONE_RESTORE,
	CTL_ZONE_SIGN,
	CTL_ZONE_KEYS_LOAD,
	CTL_ZONE_KEY_ROLL,
	CTL_ZONE_KSK_SBM,
	CTL_ZONE_FREEZE,
	CTL_ZONE_THAW,
	CTL_ZONE_XFR_FREEZE,
	CTL_ZONE_XFR_THAW,

	CTL_ZONE_READ,
	CTL_ZONE_BEGIN,
	CTL_ZONE_COMMIT,
	CTL_ZONE_ABORT,
	CTL_ZONE_DIFF,
	CTL_ZONE_GET,
	CTL_ZONE_SET,
	CTL_ZONE_UNSET,
	CTL_ZONE_PURGE,
	CTL_ZONE_STATS,

	CTL_CONF_LIST,
	CTL_CONF_READ,
	CTL_CONF_BEGIN,
	CTL_CONF_COMMIT,
	CTL_CONF_ABORT,
	CTL_CONF_DIFF,
	CTL_CONF_GET,
	CTL_CONF_SET,
	CTL_CONF_UNSET,
} ctl_cmd_t;

/*! Control command parameters. */
typedef struct {
	knot_ctl_t *ctl;
	knot_ctl_type_t type;
	knot_ctl_data_t data;
	server_t *server;
	bool suppress;	// Suppress error reporting in the "all zones" ctl commands.
} ctl_args_t;

/*!
 * Returns a string equivalent of the command.
 *
 * \param[in] cmd  Command.
 *
 * \return Command string or NULL.
 */
const char *ctl_cmd_to_str(ctl_cmd_t cmd);

/*!
 * Returns a command corresponding to the string.
 *
 * \param[in] cmd_str  Command string.
 *
 * \return Command.
 */
ctl_cmd_t ctl_str_to_cmd(const char *cmd_str);

/*!
 * Executes a control command.
 *
 * \param[in] cmd   Control command.
 * \param[in] args  Command arguments.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int ctl_exec(ctl_cmd_t cmd, ctl_args_t *args);

/*!
 * Checks flag presence in flags.
 *
 * \param[in] flags  Flags to check presence in.
 * \param[in] flag   Checked flag.
 *
 * \return True if presented.
 */
bool ctl_has_flag(const char *flags, const char *flag);
