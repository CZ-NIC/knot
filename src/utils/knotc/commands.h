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
 * \brief Knot control commands.
 *
 * \addtogroup knot_utils
 * @{
 */

#pragma once

/*! \brief Command parameter flags. */
typedef enum {
	CMD_FNONE  = 0,      /*!< Empty flag. */
	CMD_FFORCE = 1 << 0  /*!< Forced operation. */
} cmd_flag_t;

/*! \brief Command condition flags. */
typedef enum {
	CMD_CONF_FNONE  = 0,      /*!< Empty flag. */
	CMD_CONF_FREAD  = 1 << 0, /*!< Required read access to config or confdb. */
	CMD_CONF_FWRITE = 1 << 1  /*!< Required write access to confdb. */
} cmd_conf_flag_t;

/*! \brief Command callback arguments. */
typedef struct {
	char *socket;
	int argc;
	char **argv;
	cmd_flag_t flags;
} cmd_args_t;

/*! \brief Command callback prototype. */
typedef int (*cmd_t)(cmd_args_t *args);

/*! \brief Command callback description. */
typedef struct {
	const char *name;
	cmd_t cmd;
	cmd_conf_flag_t flags;
} cmd_desc_t;

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
