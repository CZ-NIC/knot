/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/log.h"
#include "knot/ctl/commands.h"
#include "knot/ctl/process.h"
#include "libknot/error.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/string.h"

int ctl_process(knot_ctl_t *ctl, server_t *server, int thread_idx, bool *exclusive)
{
	if (ctl == NULL || server == NULL) {
		return KNOT_EINVAL;
	}

	ctl_args_t args = {
		.ctl = ctl,
		.type = KNOT_CTL_TYPE_END,
		.server = server,
		.thread_idx = thread_idx,
	};

	// Strip redundant/unprocessed data units in the current block.
	bool strip = false;

	while (true) {
		// Receive data unit.
		int cmd_exec = true, cmd_ret = KNOT_EOK;
		int ret = knot_ctl_receive(args.ctl, &args.type, &args.data);
		if (ret != KNOT_EOK) {
			log_ctl_debug("control, failed to receive (%s)",
			              knot_strerror(ret));
			return ret;
		}

		// Decide what to do.
		switch (args.type) {
		case KNOT_CTL_TYPE_DATA:
			// Leading data unit with a command name.
			if (!strip) {
				// Set to strip unprocessed data unit.
				strip = true;
				break;
			}
			// FALLTHROUGH
		case KNOT_CTL_TYPE_EXTRA:
			// All non-first data units should be parsed in a callback.
			// Ignore if probable previous error.
			continue;
		case KNOT_CTL_TYPE_BLOCK:
			strip = false;
			continue;
		case KNOT_CTL_TYPE_END:
			return KNOT_EOF;
		default:
			assert(0);
		}

		strtolower((char *)args.data[KNOT_CTL_IDX_ZONE]);

		const char *cmd_name = args.data[KNOT_CTL_IDX_CMD];
		const char *zone_name = args.data[KNOT_CTL_IDX_ZONE];
		const char *flags = args.data[KNOT_CTL_IDX_FLAGS];
		const char *filters = args.data[KNOT_CTL_IDX_FILTERS];

		char buff[32];
		char extra[64] = { 0 };
		if (log_enabled_debug() && flags != NULL && strlen(flags) > 0) {
			(void)snprintf(buff, sizeof(buff), ", flags '%s'", flags);
			strlcat(extra, buff, sizeof(extra));
		}
		if (log_enabled_debug() && filters != NULL && strlen(filters) > 0) {
			(void)snprintf(buff, sizeof(buff), ", filters '%s'", filters);
			strlcat(extra, buff, sizeof(extra));
		}

		ctl_cmd_t cmd = ctl_str_to_cmd(cmd_name);
		if (cmd == CTL_CONF_LIST) {
			log_ctl_debug("control, received command '%s'%s", cmd_name, extra);
		} else if (cmd != CTL_NONE) {
			if (zone_name != NULL) {
				log_ctl_zone_str_info(zone_name,
				             "control, received command '%s'%s", cmd_name, extra);
			} else {
				log_ctl_info("control, received command '%s'%s", cmd_name, extra);
			}
		} else if (cmd_name != NULL){
			log_ctl_debug("control, invalid command '%s'%s", cmd_name, extra);
			continue;
		} else {
			log_ctl_debug("control, empty command%s", extra);
			continue;
		}

		if ((cmd == CTL_CONF_COMMIT || cmd == CTL_CONF_ABORT) && !*exclusive) {
			if (conf()->io.txn != NULL) {
				cmd_ret = KNOT_EBUSY;
			} else if (cmd == CTL_CONF_COMMIT) {
				cmd_ret = KNOT_TXN_ENOTEXISTS;
			}
			if (cmd_ret != KNOT_EOK) {
				ctl_send_error(&args, knot_strerror(cmd_ret));
			}
			cmd_exec = false;
		}

		// Execute the command.
		if (cmd_exec) {
			cmd_ret = ctl_exec(cmd, &args);
		}
		switch (cmd_ret) {
		case KNOT_EOK:
			strip = false;
			if (cmd == CTL_CONF_BEGIN) {
				*exclusive = true;
			} else if (cmd == CTL_CONF_COMMIT || cmd == CTL_CONF_ABORT) {
				*exclusive = false;
			}
		case KNOT_CTL_ESTOP:
		case KNOT_CTL_EZONE:
			// KNOT_CTL_EZONE - don't change strip, but don't be reported
			// as a ctl/communication error either.
			break;
		default:
			log_ctl_debug("control, command '%s' (%s)", cmd_name,
			              knot_strerror(cmd_ret));
			break;
		}

		// Finalize the answer block.
		ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL);
		if (ret != KNOT_EOK) {
			log_ctl_debug("control, failed to reply (%s)",
			              knot_strerror(ret));
		}

		// Stop if required.
		if (cmd_ret == KNOT_CTL_ESTOP) {
			// Finalize the answer message.
			ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_END, NULL);
			if (ret != KNOT_EOK) {
				log_ctl_debug("control, failed to reply (%s)",
				              knot_strerror(ret));
			}

			return cmd_ret;
		}
	}
}
