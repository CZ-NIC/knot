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

#pragma once

#include "knot/dnssec/context.h"

struct options {
	bool legacy;
	char *kasp_dir;
	char *config;
	char *confdb;
};

typedef struct options options_t;

int options_init(options_t *options);

void options_cleanup(options_t *options);

int options_zone_kasp_path(options_t *options, const char *zone_name);

int options_zone_kasp_init(options_t *options, const char *zone_name,
                           dnssec_kasp_t **kasp);
