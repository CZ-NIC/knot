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

#include <string.h>

#include "utils/common/lookup.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"
#include "libknot/error.h"

int lookup_init(lookup_t *lookup)
{
	if (lookup == NULL) {
		return KNOT_EINVAL;
	}
	memset(lookup, 0, sizeof(*lookup));

	mm_ctx_mempool(&lookup->mm, MM_DEFAULT_BLKSIZE);
	lookup->trie = hattrie_create(&lookup->mm);
	if (lookup->trie == NULL) {
		mp_delete(lookup->mm.ctx);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static void reset_output(lookup_t *lookup)
{
	if (lookup == NULL) {
		return;
	}

	mm_free(&lookup->mm, lookup->found.key);
	lookup->found.key = NULL;
	lookup->found.data = NULL;

	lookup->iter.count = 0;

	mm_free(&lookup->mm, lookup->iter.first_key);
	lookup->iter.first_key = NULL;

	hattrie_iter_free(lookup->iter.it);
	lookup->iter.it = NULL;
}

void lookup_deinit(lookup_t *lookup)
{
	if (lookup == NULL) {
		return;
	}

	reset_output(lookup);

	hattrie_free(lookup->trie);
	mp_delete(lookup->mm.ctx);
}

int lookup_insert(lookup_t *lookup, const char *str, void *data)
{
	if (lookup == NULL || str == NULL) {
		return KNOT_EINVAL;
	}

	size_t str_len = strlen(str);
	if (str_len == 0) {
		return KNOT_EINVAL;
	}

	value_t *val = hattrie_get(lookup->trie, str, str_len);
	if (val == NULL) {
		return KNOT_ENOMEM;
	}
	*val = data;

	return KNOT_EOK;
}

static int set_key(lookup_t *lookup, char **dst, const char *key, size_t key_len)
{
	if (*dst != NULL) {
		mm_free(&lookup->mm, *dst);
	}
	*dst = mm_alloc(&lookup->mm, key_len + 1);
	if (*dst == NULL) {
		return KNOT_ENOMEM;
	}
	memcpy(*dst, key, key_len);
	(*dst)[key_len] = '\0';

	return KNOT_EOK;
}

int lookup_search(lookup_t *lookup, const char *str, size_t str_len)
{
	if (lookup == NULL) {
		return KNOT_EINVAL;
	}

	// Change NULL string to the empty one.
	if (str == NULL) {
		str = "";
	}

	reset_output(lookup);

	size_t new_len = 0;
	hattrie_iter_t *it = hattrie_iter_begin(lookup->trie, true);
	for (; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		size_t len;
		const char *key = hattrie_iter_key(it, &len);

		// Compare with a shorter key.
		if (len < str_len) {
			int ret = memcmp(str, key, len);
			if (ret >= 0) {
				continue;
			} else {
				break;
			}
		}

		// Compare with an equal length or longer key.
		int ret = memcmp(str, key, str_len);
		if (ret == 0) {
			lookup->iter.count++;

			// First candidate.
			if (lookup->iter.count == 1) {
				ret = set_key(lookup, &lookup->found.key, key, len);
				if (ret != KNOT_EOK) {
					break;
				}
				lookup->found.data = *hattrie_iter_val(it);
				new_len = len;
			// Another candidate.
			} else if (new_len > str_len) {
				if (new_len > len) {
					new_len = len;
				}
				while (memcmp(lookup->found.key, key, new_len) != 0) {
					new_len--;
				}
			}
		// Stop if greater than the key, and also than all the following keys.
		} else if (ret < 0) {
			break;
		}
	}
	hattrie_iter_free(it);

	switch (lookup->iter.count) {
	case 0:
		return KNOT_ENOENT;
	case 1:
		return KNOT_EOK;
	default:
		// Store full name of the first candidate.
		if (set_key(lookup, &lookup->iter.first_key, lookup->found.key,
		            strlen(lookup->found.key)) != KNOT_EOK) {
			return KNOT_ENOMEM;
		}
		lookup->found.key[new_len] = '\0';
		lookup->found.data = NULL;

		return KNOT_EFEWDATA;
	}
}

void lookup_list(lookup_t *lookup)
{
	if (lookup == NULL || lookup->iter.first_key == NULL) {
		return;
	}

	if (lookup->iter.it != NULL) {
		if (hattrie_iter_finished(lookup->iter.it)) {
			hattrie_iter_free(lookup->iter.it);
			lookup->iter.it = NULL;
			return;
		}

		hattrie_iter_next(lookup->iter.it);

		size_t len;
		const char *key = hattrie_iter_key(lookup->iter.it, &len);

		int ret = set_key(lookup, &lookup->found.key, key, len);
		if (ret == KNOT_EOK) {
			lookup->found.data = *hattrie_iter_val(lookup->iter.it);
		}
		return;
	}

	lookup->iter.it = hattrie_iter_begin(lookup->trie, true);
	while (!hattrie_iter_finished(lookup->iter.it)) {
		size_t len;
		const char *key = hattrie_iter_key(lookup->iter.it, &len);

		if (strcmp(key, lookup->iter.first_key) == 0) {
			int ret = set_key(lookup, &lookup->found.key, key, len);
			if (ret == KNOT_EOK) {
				lookup->found.data = *hattrie_iter_val(lookup->iter.it);
			}
			break;
		}
		hattrie_iter_next(lookup->iter.it);
	}
}

static void print_options(lookup_t *lookup, EditLine *el)
{
	// Get terminal lines.
	unsigned lines = 0;
	if (el_get(el, EL_GETTC, "li", &lines) != 0 || lines < 3) {
		return;
	}

	for (size_t i = 1; i <= lookup->iter.count; i++) {
		lookup_list(lookup);
		printf("\n%s", lookup->found.key);

		if (i > 1 && i % (lines - 1) == 0 && i < lookup->iter.count) {
			printf("\n Display next from %zu possibilities? (y or n)",
			       lookup->iter.count);
			char next;
			el_getc(el, &next);
			if (next != 'y') {
				break;
			}
		}
	}

	printf("\n");
	fflush(stdout);
}

void lookup_complete(lookup_t *lookup, const char *str, size_t str_len,
                     EditLine *el, bool add_space)
{
	if (lookup == NULL || el == NULL) {
		return;
	}

	// Try to complete the command name.
	int ret = lookup_search(lookup, str, str_len);
	switch (ret) {
	case KNOT_EOK:
		el_deletestr(el, str_len);
		el_insertstr(el, lookup->found.key);
		if (add_space) {
			el_insertstr(el, " ");
		}
		break;
	case KNOT_EFEWDATA:
		if (strlen(lookup->found.key) > str_len) {
			el_deletestr(el, str_len);
			el_insertstr(el, lookup->found.key);
		} else {
			print_options(lookup, el);
		}
		break;
	default:
		break;
	}
}
