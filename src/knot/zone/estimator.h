/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "common/hattrie/ahtable.h"
#include "zscanner/scanner.h"

typedef struct zone_estim {
	hattrie_t *node_table;
	hattrie_t *dname_table;
	size_t rdata_size;
	size_t dname_size;
	size_t node_size;
	size_t ahtable_size;
	size_t rrset_size;
	size_t record_count;
	size_t signed_count;
} zone_estim_t;


void *estimator_malloc(void* ctx, size_t len);
void estimator_free(void *p);
size_t estimator_trie_ahtable_memsize(hattrie_t *table);
void estimator_rrset_memsize_wrap(const scanner_t *scanner);
void estimator_free_trie_node(value_t *val, void *data);
