/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/qp-trie/trie.h"

#include "libknot/dname.h"
#include "libknot/error.h"

typedef trie_t knot_catalog_t;

typedef struct {
	knot_dname_t *zone;
	char *conf_template;
} knot_catalog_val_t;

typedef struct {
	knot_catalog_t *rem;
	knot_catalog_t *add;
} knot_catalog_change_t;

typedef int (*knot_catalog_cb_t)(knot_catalog_val_t *, void *);

knot_catalog_t *knot_catalog_new(void);

int knot_catalog_foreach(knot_catalog_t *catalog, knot_catalog_cb_t *cb, void *ctx);

int knot_catalog_add(knot_catalog_t *catalog, const knot_dname_t *zone, const char *tpl);

knot_catalog_val_t *knot_catalog_get(knot_catalog_t *catalog, const knot_dname_t *zone);

void knot_catalog_del(knot_catalog_t *catalog, const knot_dname_t *zone);

void knot_catalog_clear(knot_catalog_t *catalog);

void knot_catalog_free(knot_catalog_t *catalog);

int knot_catalog_change_new(knot_catalog_change_t *ch);

void knot_catalog_change_free(knot_catalog_change_t *ch);
