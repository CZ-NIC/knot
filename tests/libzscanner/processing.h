/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libzscanner/scanner.h"

void debug_process_error(zs_scanner_t *scanner);

void debug_process_record(zs_scanner_t *scanner);

void debug_process_comment(zs_scanner_t *scanner);

void test_process_error(zs_scanner_t *scanner);

void test_process_record(zs_scanner_t *scanner);

int test_date_to_timestamp(void);
