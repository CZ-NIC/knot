/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/control/control.h"
#include "knot/ctl/commands.h"

#define CMD_EXIT		"exit"

#define CMD_STATUS		"status"
#define CMD_STOP		"stop"
#define CMD_RELOAD		"reload"
#define CMD_STATS		"stats"

#define CMD_ZONE_CHECK		"zone-check"
#define CMD_ZONE_STATUS		"zone-status"
#define CMD_ZONE_RELOAD		"zone-reload"
#define CMD_ZONE_REFRESH	"zone-refresh"
#define CMD_ZONE_RETRANSFER	"zone-retransfer"
#define CMD_ZONE_NOTIFY		"zone-notify"
#define CMD_ZONE_FLUSH		"zone-flush"
#define CMD_ZONE_BACKUP		"zone-backup"
#define CMD_ZONE_RESTORE	"zone-restore"
#define CMD_ZONE_SIGN		"zone-sign"
#define CMD_ZONE_VALIDATE	"zone-validate"
#define CMD_ZONE_KEYS_LOAD	"zone-keys-load"
#define CMD_ZONE_KEY_ROLL	"zone-key-rollover"
#define CMD_ZONE_KSK_SBM	"zone-ksk-submitted"
#define CMD_ZONE_FREEZE		"zone-freeze"
#define CMD_ZONE_THAW		"zone-thaw"
#define CMD_ZONE_XFR_FREEZE	"zone-xfr-freeze"
#define CMD_ZONE_XFR_THAW	"zone-xfr-thaw"

#define CMD_ZONE_READ		"zone-read"
#define CMD_ZONE_BEGIN		"zone-begin"
#define CMD_ZONE_COMMIT		"zone-commit"
#define CMD_ZONE_ABORT		"zone-abort"
#define CMD_ZONE_DIFF		"zone-diff"
#define CMD_ZONE_GET		"zone-get"
#define CMD_ZONE_SET		"zone-set"
#define CMD_ZONE_UNSET		"zone-unset"
#define CMD_ZONE_PURGE		"zone-purge"
#define CMD_ZONE_STATS		"zone-stats"

#define CMD_CONF_INIT		"conf-init"
#define CMD_CONF_CHECK		"conf-check"
#define CMD_CONF_IMPORT		"conf-import"
#define CMD_CONF_EXPORT		"conf-export"
#define CMD_CONF_LIST		"conf-list"
#define CMD_CONF_READ		"conf-read"
#define CMD_CONF_BEGIN		"conf-begin"
#define CMD_CONF_COMMIT		"conf-commit"
#define CMD_CONF_ABORT		"conf-abort"
#define CMD_CONF_DIFF		"conf-diff"
#define CMD_CONF_GET		"conf-get"
#define CMD_CONF_SET		"conf-set"
#define CMD_CONF_UNSET		"conf-unset"

/*! \brief Command condition flags. */
typedef enum {
	CMD_FNONE        = 0,       /*!< Empty flag. */
	CMD_FREAD        = 1 << 0,  /*!< Required read access to config or confdb. */
	CMD_FWRITE       = 1 << 1,  /*!< Required write access to confdb. */
	CMD_FOPT_ITEM    = 1 << 2,  /*!< Optional item argument. */
	CMD_FREQ_ITEM    = 1 << 3,  /*!< Required item argument. */
	CMD_FOPT_DATA    = 1 << 4,  /*!< Optional item data argument. */
	CMD_FOPT_ZONE    = 1 << 5,  /*!< Optional zone name argument. */
	CMD_FREQ_ZONE    = 1 << 6,  /*!< Required zone name argument. */
	CMD_FREQ_TXN     = 1 << 7,  /*!< Required open confdb transaction. */
	CMD_FOPT_MOD     = 1 << 8,  /*!< Optional configured modules dependency. */
	CMD_FREQ_MOD     = 1 << 9,  /*!< Required configured modules dependency. */
	CMD_FLIST_SCHEMA = 1 << 10, /*!< List schema or possible option values. */
	CMD_FOPT_FILTER  = 1 << 11, /*!< Optional filter argument. */
	CMD_FLOG_MORE    = 1 << 12, /*!< Execute command with increased log level. */
} cmd_flag_t;

struct cmd_desc;
typedef struct cmd_desc cmd_desc_t;

/*! \brief Command callback arguments. */
typedef struct {
	const cmd_desc_t *desc;
	knot_ctl_t *ctl;
	int argc;
	const char **argv;
	char flags[4];
	bool force;
	bool extended;
	bool color;
	bool color_force;
	bool blocking;
} cmd_args_t;

/*! \brief Command callback description. */
struct cmd_desc {
	const char *name;
	int (*fcn)(cmd_args_t *);
	ctl_cmd_t cmd;
	cmd_flag_t flags;
};

/*! \brief Command description. */
typedef struct {
	const char *name;
	const char *params;
	const char *desc;
} cmd_help_t;

/*! Control command filter description. */
typedef struct {
	const char *name;
	char *id;
	bool with_data; // Only ONE filter of each filter_desc_t may have data!
} filter_desc_t;

/*! Exported filter descriptions. */
extern const filter_desc_t conf_import_filters[];
extern const filter_desc_t conf_export_filters[];
extern const filter_desc_t zone_begin_filters[];
extern const filter_desc_t zone_flush_filters[];
extern const filter_desc_t zone_backup_filters[];
extern const filter_desc_t zone_status_filters[];
extern const filter_desc_t zone_purge_filters[];

/*! \brief Table of commands. */
extern const cmd_desc_t cmd_table[];

/*! \brief Prints commands help. */
void print_commands(void);
