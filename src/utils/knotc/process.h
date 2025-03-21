/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "utils/knotc/commands.h"

#define DEFAULT_CTL_TIMEOUT_MS	(60 * 1000)

/*! Utility command line parameters. */
typedef struct {
	const char *orig_config;
	const char *orig_confdb;
	const char *config;
	const char *confdb;
	size_t max_conf_size;
	const char *socket;
	bool verbose;
	bool extended;
	bool force;
	bool blocking;
	int timeout;
	bool color;
	bool color_force;
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
 * Establishes a control interface if necessary.
 *
 * \param[in] ctl      Control context.
 * \param[in] socket   Control socket path.
 * \param[in] timeout  Control socket timeout.
 * \param[in] desc     Utility command descriptor.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int set_ctl(knot_ctl_t **ctl, const char *socket, int timeout, const cmd_desc_t *desc);

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
