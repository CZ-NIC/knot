/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "cmdparse/parameter.h"

/*!
 * bool (set only)
 */
int value_flag(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * bool
 */
int value_bool(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * char *
 */
int value_string(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * const char *
 */
int value_static_string(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * dnssec_key_algorithm_t
 */
int value_algorithm(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * dnssec_tsig_algorithm_t
 */
int value_tsig_algorithm(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * unsigned int
 */
int value_key_size(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * uint32_t
 */
int value_uint32(int argc, char *argv[], const parameter_t *p, void *data);

/*!
 * time_t
 */
int value_time(int argc, char *argv[], const parameter_t *p, void *data);
