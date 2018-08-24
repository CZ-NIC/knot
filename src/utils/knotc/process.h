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

#include "utils/knotc/commands.h"

/*! Utility command line parameters. */
typedef struct {
	const char *config;
	const char *confdb;
	size_t max_conf_size;
	const char *socket;
	bool verbose;
	bool force;
	int timeout;
} params_t;

/*!
 * Prepares a proper configuration according to the specified command.
 *
 * \param[in] desc    Utility command descriptor.
 * \param[in] params  Utility parameters.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int set_config(const cmd_desc_t *desc, params_t *params);

/*!
 * Estabilishes a control interface if necessary.
 *
 * \param[in] ctl     Control context.
 * \param[in] desc    Utility command descriptor.
 * \param[in] params  Utility parameters.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int set_ctl(knot_ctl_t **ctl, const cmd_desc_t *desc, params_t *params);

/*!
 * Cleans up the control context.
 *
 * \param[in] ctl     Control context.
 */
void unset_ctl(knot_ctl_t *ctl);

/*!
 * Processes the given utility command.
 *
 * \param[in] argc    Number of command arguments.
 * \param[in] argv    Command arguments.
 * \param[in] params  Utility parameters.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int process_cmd(int argc, const char **argv, params_t *params);
