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

#include "contrib/qp-trie/qp.h"

typedef trie_t hattrie_t;
typedef trie_val_t value_t;
typedef trie_it_t hattrie_iter_t;

inline static hattrie_t* hattrie_create(struct knot_mm *mm)
{
	return trie_create(mm);
}

inline static void hattrie_free(hattrie_t *trie)
{
	trie_free(trie);
}

inline static void hattrie_clear(hattrie_t *trie)
{
	trie_clear(trie);
}

inline static size_t hattrie_weight(const hattrie_t *trie)
{
	return trie_weight(trie);
}

inline static int hattrie_apply_rev(hattrie_t *trie, int (*f)(value_t*,void*), void* d)
{
	return trie_apply(trie, f, d);
}

inline static value_t* hattrie_tryget(hattrie_t *trie, const char *key, size_t len)
{
	return trie_get_try(trie, key, len);
}

inline static value_t* hattrie_get(hattrie_t *trie, const char *key, size_t len)
{
	return trie_get_ins(trie, key, len);
}

inline static int hattrie_find_leq(hattrie_t *trie, const char *key, size_t len, value_t **dst)
{
	return trie_get_leq(trie, key, len, dst);
}

inline static int hattrie_del(hattrie_t *trie, const char* key, size_t len, value_t *val)
{
	return trie_del(trie, key, len, val);
}

inline static hattrie_iter_t* hattrie_iter_begin(hattrie_t *trie)
{
	return trie_it_begin(trie);
}

inline static void hattrie_iter_next(hattrie_iter_t *it)
{
	trie_it_next(it);
}

inline static bool hattrie_iter_finished(hattrie_iter_t *it)
{
	return trie_it_finished(it);
}

inline static void hattrie_iter_free(hattrie_iter_t *it)
{
	trie_it_free(it);
}

inline static const char* hattrie_iter_key(hattrie_iter_t *it, size_t *len)
{
	return trie_it_key(it, len);
}

inline static value_t* hattrie_iter_val(hattrie_iter_t *it)
{
	return trie_it_val(it);
}
