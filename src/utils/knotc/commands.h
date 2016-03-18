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
 * \brief Knot control commands.
 *
 * \addtogroup knot_utils
 * @{
 */

#pragma once

#include "libknot/control/control.h"
#include "knot/ctl/commands.h"

/*! \brief Command parameter flags. */
typedef enum {
	CMD_FNONE  = 0,      /*!< Empty flag. */
	CMD_FFORCE = 1 << 0, /*!< Forced operation. */
} cmd_flag_t;

/*! \brief Command condition flags. */
typedef enum {
	CMD_CONF_FNONE     = 0,      /*!< Empty flag. */
	CMD_CONF_FREAD     = 1 << 0, /*!< Required read access to config or confdb. */
	CMD_CONF_FWRITE    = 1 << 1, /*!< Required write access to confdb. */
	CMD_CONF_FOPT_ITEM = 1 << 2, /*!< Optional item argument. */
	CMD_CONF_FREQ_ITEM = 1 << 3, /*!< Required item argument. */
	CMD_CONF_FOPT_DATA = 1 << 4, /*!< Optional item data argument. */
} cmd_conf_flag_t;

struct cmd_desc;
typedef struct cmd_desc cmd_desc_t;

/*! \brief Command callback arguments. */
typedef struct {
	const cmd_desc_t *desc;
	knot_ctl_t *ctl;
	int argc;
	char **argv;
	cmd_flag_t flags;
} cmd_args_t;

/*! \brief Command callback description. */
struct cmd_desc {
	const char *name;
	int (*fcn)(cmd_args_t *);
	ctl_cmd_t cmd;
	cmd_conf_flag_t flags;
};

/*! \brief Old command name translation. */
typedef struct {
	const char *old_name;
	const char *new_name;
} cmd_desc_old_t;

/*! \brief Command description. */
typedef struct {
	const char *name;
	const char *params;
	const char *desc;
} cmd_help_t;

/*! \brief Table of commands. */
extern const cmd_desc_t cmd_table[];

/*! \brief Table of command translations. */
extern const cmd_desc_old_t cmd_table_old[];

/*! \brief Table of command descriptions. */
extern const cmd_help_t cmd_help_table[];

/*! @} */
