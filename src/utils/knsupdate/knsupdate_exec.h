/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "utils/knsupdate/knsupdate_params.h"

extern const char* knsupdate_cmd_array[];

int knsupdate_exec(knsupdate_params_t *params);

int knsupdate_process_line(const char *line, knsupdate_params_t *params);
