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

#define check_prefix		check_prefix_rm
#define synth_record_conf	synth_record_conf_rm
#define synth_record_conf_check	synth_record_conf_check_rm
#define synth_record_load	synth_record_load_rm
#define synth_record_unload	synth_record_unload_rm
#include "knot/modules/synthrecord/synthrecord.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// Skip invalid dnames.
	if (knot_dname_wire_check(data, data + size, NULL) <= 0) {
		return 0;
	}

	const synth_template_t template = {
		.type = SYNTH_FORWARD,
		.prefix = "ip-",
		.prefix_len = 3
	};
	knotd_qdata_t qdata = {
		.name = (knot_dname_t *)data
	};

	int provided_af = AF_UNSPEC;
	char addr_str[SOCKADDR_STRLEN];

	(void)addr_parse(&qdata, &template, addr_str, &provided_af, NULL);

	return 0;
}
