/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdlib.h>
#include <assert.h>

#include "knot/updates/changesets.h"
#include "libknot/common.h"
#include "common/descriptor.h"
#include "common/mempattern.h"
#include "common/mempool.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/soa.h"
#include "common/debug.h"

void changeset_init(changeset_t *ch, mm_ctx_t *mm)
{
	memset(ch, 0, sizeof(changeset_t));

	ch->mm = mm;

	// Init local lists
	init_list(&ch->add);
	init_list(&ch->remove);

	// Init change lists
	init_list(&ch->new_data);
	init_list(&ch->old_data);
}

changeset_t *changeset_new(mm_ctx_t *mm)
{
	changeset_t *ret = mm_alloc(mm, sizeof(changeset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	changeset_init(ret, mm);
	return ret;
}

int changeset_add_rrset(changeset_t *ch, knot_rrset_t *rrset,
                        changeset_part_t part)
{
	if (part == CHANGESET_ADD) {
		if (ptrlist_add(&ch->add, rrset, ch->mm) == NULL) {
			return KNOT_ENOMEM;
		}
	} else {
		if (ptrlist_add(&ch->remove, rrset, ch->mm) == NULL) {
			return KNOT_ENOMEM;
		}
	}

	return KNOT_EOK;
}

bool changeset_empty(const changeset_t *ch)
{
	if (ch == NULL) {
		return true;
	}

	return (ch->soa_to == NULL &&
	        EMPTY_LIST(ch->add) && EMPTY_LIST(ch->remove));
}

size_t changeset_size(const changeset_t *ch)
{
	if (!ch || changeset_empty(ch)) {
		return 0;
	}

	return list_size(&ch->add) + list_size(&ch->remove);
}

int changeset_apply(changeset_t *ch, changeset_part_t part,
                    int (*func)(knot_rrset_t *, void *), void *data)
{
	if (ch == NULL || func == NULL) {
		return KNOT_EINVAL;
	}

	ptrnode_t *n;
	if (part == CHANGESET_ADD) {
		WALK_LIST(n, ch->add) {
			int res = func((knot_rrset_t *)n->d, data);
			if (res != KNOT_EOK) {
				return res;
			}
		}
	} else if (part == CHANGESET_REMOVE) {
		WALK_LIST(n, ch->remove) {
			int res = func((knot_rrset_t *)n->d, data);
			if (res != KNOT_EOK) {
				return res;
			}
		}
	}

	return KNOT_EOK;
}

void changeset_merge(changeset_t *ch1, changeset_t *ch2)
{
	// Connect lists in changesets together
	add_tail_list(&ch1->add, &ch2->add);
	add_tail_list(&ch1->remove, &ch2->remove);

	// Use soa_to and serial from the second changeset
	// soa_to from the first changeset is redundant, delete it
	knot_rrset_free(&ch1->soa_to, NULL);
	ch1->soa_to = ch2->soa_to;
}

void changeset_clear(changeset_t *ch, mm_ctx_t *rr_mm)
{
	if (ch == NULL) {
		return;
	}

	// Delete RRSets in lists, in case there are any left
	ptrnode_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, ch->add) {
		knot_rrset_free((knot_rrset_t **)&n->d, rr_mm);
		mm_free(ch->mm, n);
	}
	WALK_LIST_DELSAFE(n, nxt, ch->remove) {
		knot_rrset_free((knot_rrset_t **)&n->d, rr_mm);
		mm_free(ch->mm, n);
	}

	knot_rrset_free(&ch->soa_from, rr_mm);
	knot_rrset_free(&ch->soa_to, rr_mm);

	// Delete binary data
	free(ch->data);
}

void changesets_free(list_t *chgs, mm_ctx_t *rr_mm)
{
	if (!EMPTY_LIST(*chgs)) {
		changeset_t *chg, *nxt;
		WALK_LIST_DELSAFE(chg, nxt, *chgs) {
			changeset_clear(chg, rr_mm);
			free(chg);
		}
	}
}

