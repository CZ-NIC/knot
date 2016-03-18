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

#include "knot/common/log.h"
#include "knot/ctl/commands.h"
#include "knot/ctl/process.h"
#include "libknot/error.h"

int ctl_process(knot_ctl_t *ctl, server_t *server)
{
	if (ctl == NULL || server == NULL) {
		return KNOT_EINVAL;
	}

	ctl_args_t args = {
		.ctl = ctl,
		.type = KNOT_CTL_TYPE_END,
		.server = server
	};

	// Strip redundant/unprocessed data units in the current block.
	bool strip = false;

	while (true) {
		// Receive data unit.
		int ret = knot_ctl_receive(args.ctl, &args.type, &args.data);
		if (ret != KNOT_EOK) {
			log_debug("control, failed to receive (%s)",
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

		const char *cmd_name = args.data[KNOT_CTL_IDX_CMD];

		ctl_cmd_t cmd = ctl_str_to_cmd(cmd_name);
		if (cmd != CTL_NONE) {
			log_info("control, received command '%s'", cmd_name);
		} else if (cmd_name != NULL){
			log_debug("control, invalid command '%s'", cmd_name);
			continue;
		} else {
			log_debug("control, empty command");
			continue;
		}

		// Execute the command.
		int cmd_ret = ctl_exec(cmd, &args);
		switch (cmd_ret) {
		case KNOT_EOK:
			strip = false;
		case KNOT_CTL_ESTOP:
			break;
		default:
			log_debug("control, command '%s' (%s)", cmd_name,
			          knot_strerror(cmd_ret));
			break;
		}

		// Finalize the answer block.
		ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL);
		if (ret != KNOT_EOK) {
			log_debug("control, failed to reply (%s)",
			          knot_strerror(ret));
		}

		// Stop if required.
		if (cmd_ret == KNOT_CTL_ESTOP) {
			// Finalize the answer message.
			ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_END, NULL);
			if (ret != KNOT_EOK) {
				log_debug("control, failed to reply (%s)",
				          knot_strerror(ret));
			}

			return cmd_ret;
		}
	}
}
