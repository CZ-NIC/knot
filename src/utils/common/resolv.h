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

#include "utils/common/netio.h"
#include "contrib/ucw/lists.h"


typedef struct {
	list_t domains;
	struct {
		int ndots;
	} options;

} resolv_conf_t;

typedef struct {
	node_t head, tail;
	size_t len;
	char domain[0];
} resolv_domain_t;

void resolv_conf_init(resolv_conf_t *conf);

void resolv_conf_deinit(resolv_conf_t *conf);

srv_info_t* parse_nameserver(const char *str, const char *def_port);

void get_nameservers(list_t *servers, const char *def_port);

int get_domains(resolv_conf_t *conf);