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

#include "libzscanner/scanner.h"

void debug_process_error(zs_scanner_t *scanner);

void debug_process_record(zs_scanner_t *scanner);

void debug_process_comment(zs_scanner_t *scanner);

void test_process_error(zs_scanner_t *scanner);

void test_process_record(zs_scanner_t *scanner);

int test_date_to_timestamp(void);
