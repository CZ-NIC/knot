/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/control/control.h"
#include "knot/ctl/commands.h"

/*! \brief Command condition flags. */
typedef enum {
	CMD_FNONE      = 0,      /*!< Empty flag. */
	CMD_FREAD      = 1 << 0, /*!< Required read access to config or confdb. */
	CMD_FWRITE     = 1 << 1, /*!< Required write access to confdb. */
	CMD_FOPT_ITEM  = 1 << 2, /*!< Optional item argument. */
	CMD_FREQ_ITEM  = 1 << 3, /*!< Required item argument. */
	CMD_FOPT_DATA  = 1 << 4, /*!< Optional item data argument. */
	CMD_FOPT_ZONE  = 1 << 5, /*!< Optional zone name argument. */
	CMD_FREQ_ZONE  = 1 << 6, /*!< Required zone name argument. */
	CMD_FREQ_TXN   = 1 << 7, /*!< Required open confdb transaction. */
	CMD_FOPT_MOD   = 1 << 8, /*!< Optional configured modules dependency. */
	CMD_FREQ_MOD   = 1 << 9, /*!< Required configured modules dependency. */
} cmd_flag_t;

struct cmd_desc;
typedef struct cmd_desc cmd_desc_t;

/*! \brief Command callback arguments. */
typedef struct {
	const cmd_desc_t *desc;
	knot_ctl_t *ctl;
	int argc;
	const char **argv;
	bool force;
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

/*! \brief Table of commands. */
extern const cmd_desc_t cmd_table[];

/*! \brief Prints commands help. */
void print_commands(void);
