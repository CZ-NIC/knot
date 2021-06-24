/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#define CTL_FILTER_FLUSH_OUTDIR		'd'

#define CTL_FILTER_STATUS_ROLE		'r'
#define CTL_FILTER_STATUS_SERIAL	's'
#define CTL_FILTER_STATUS_TRANSACTION	't'
#define CTL_FILTER_STATUS_FREEZE	'f'
#define CTL_FILTER_STATUS_EVENTS	'e'

#define CTL_FILTER_PURGE_EXPIRE		'e'
#define CTL_FILTER_PURGE_ZONEFILE	'f'
#define CTL_FILTER_PURGE_JOURNAL	'j'
#define CTL_FILTER_PURGE_TIMERS		't'
#define CTL_FILTER_PURGE_KASPDB		'k'
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
	bool suppress : 1;	// Suppress error reporting in the "all zones" ctl commands.
	bool strip : 1;
	bool init_recv : 1;
} ctl_args_t;

typedef struct ctl_args_queue {
	size_t begin, stored, size;
	ctl_args_t *array;
} ctl_args_queue_t;
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
 * Logs control data items at the debug level.
 *
 * \param[in] data  Control data.
 */
void ctl_log_data(knot_ctl_data_t *data);

/*!
 * Checks flag presence in flags.
 *
 * \param[in] flags  Flags to check presence in.
 * \param[in] flag   Checked flag.
 *
 * \return True if presented.
 */
bool ctl_has_flag(const char *flags, const char *flag);

/*!
 * Tells whether the command should run in the background.
 *
 * \param[in] cmd  Control command.
 *
 * \return True if should run in background.
 */
bool ctl_cmd_is_background(ctl_cmd_t cmd);

/*!
 * Create new queue for `ctl_args_t` of desired max size.
 *
 * \param[in] ctx  Queue context.
 * \param[in] size Maximal size of queue.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int ctl_args_queue_init(ctl_args_queue_t *ctx, const size_t size);

/*!
 * Tells whether queue is full.
 *
 * \param[in] ctx Queue context.
 *
 * \return True if queue is full.
 */
bool ctl_args_queue_is_full(const ctl_args_queue_t *ctx);

/*!
 * Tells whether queue is empty.
 *
 * \param[in] ctx Queue context.
 *
 * \return True if queue is empty.
 */
bool ctl_args_queue_is_empty(const ctl_args_queue_t *ctx);

/*!
 * Return pointer on the first `ctl_args_t` in queue.
 *
 * \param[in] ctx Queue context.
 *
 * \return NULL if empty, pointer on first if success.
 */
ctl_args_t *ctl_args_queue_top(const ctl_args_queue_t *ctx);

/*!
 * Store copy of `ctl_args_t` on the end of queue.
 *
 * \param[in] ctx Queue context.
 * \param[in] el  Arguments to store.
 *
 * \return NULL on error, pointer on stored if success.
 */
ctl_args_t *ctl_args_queue_enqueue(ctl_args_queue_t *ctx, const ctl_args_t *el);

/*!
 * Remove first `ctl_args_t` from queue.
 *
 * \param[in] ctx Queue context.
 */
void ctl_args_queue_dequeue(ctl_args_queue_t *ctx);

/*!
 * Deinitialize queue.
 *
 * \param[in] ctx Queue context.
 */
void ctl_args_queue_deinit(ctl_args_queue_t *ctx);