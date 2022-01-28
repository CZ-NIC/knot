/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>

#include "knot/updates/changesets.h"
#include "knot/updates/apply.h"
#include "knot/zone/zone-dump.h"
#include "contrib/color.h"
#include "contrib/time.h"
#include "libknot/libknot.h"

static int handle_soa(knot_rrset_t **soa, const knot_rrset_t *rrset)
{
	assert(soa);
	assert(rrset);

	if (*soa != NULL) {
		knot_rrset_free(*soa, NULL);
	}

	*soa = knot_rrset_copy(rrset, NULL);
	if (*soa == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Adds RRSet to given zone. */
static int add_rr_to_contents(zone_contents_t *z, const knot_rrset_t *rrset)
{
	_unused_ zone_node_t *n = NULL;
	int ret = zone_contents_add_rr(z, rrset, &n);

	// We don't care of TTLs.
	return ret == KNOT_ETTL ? KNOT_EOK : ret;
}

/*! \brief Inits changeset iterator with given tries. */
static int changeset_iter_init(changeset_iter_t *ch_it, size_t tries, ...)
{
	memset(ch_it, 0, sizeof(*ch_it));

	va_list args;
	va_start(args, tries);

	assert(tries <= sizeof(ch_it->trees) / sizeof(*ch_it->trees));
	for (size_t i = 0; i < tries; ++i) {
		zone_tree_t *t = va_arg(args, zone_tree_t *);
		if (t == NULL) {
			continue;
		}

		ch_it->trees[ch_it->n_trees++] = t;
	}

	va_end(args);

	assert(ch_it->n_trees);
	return zone_tree_it_begin(ch_it->trees[0], &ch_it->it);
}

// removes from counterpart what is in rr.
// fixed_rr is an output parameter, holding a copy of rr without what has been removed from counterpart
static void check_redundancy(zone_contents_t *counterpart, const knot_rrset_t *rr, knot_rrset_t **fixed_rr)
{
	if (fixed_rr != NULL) {
		*fixed_rr = knot_rrset_copy(rr, NULL);
	}

	zone_node_t *node = zone_contents_find_node_for_rr(counterpart, rr);
	if (node == NULL) {
		return;
	}

	if (!node_rrtype_exists(node, rr->type)) {
		return;
	}

	uint32_t rrs_ttl = node_rrset(node, rr->type).ttl;

	if (fixed_rr != NULL && *fixed_rr != NULL &&
	    ((*fixed_rr)->ttl == rrs_ttl || rr->type == KNOT_RRTYPE_RRSIG)) {
		int ret = knot_rdataset_subtract(&(*fixed_rr)->rrs, node_rdataset(node, rr->type), NULL);
		if (ret != KNOT_EOK) {
			return;
		}
	}

	// TTL of RRSIGs is better determined by original_ttl field, which is compared as part of rdata anyway
	if (rr->ttl == rrs_ttl || rr->type == KNOT_RRTYPE_RRSIG) {
		int ret = node_remove_rrset(node, rr, NULL);
		if (ret != KNOT_EOK) {
			return;
		}
	}

	if (node->rrset_count == 0 && node->children == 0 && node != counterpart->apex) {
		zone_tree_t *t = knot_rrset_is_nsec3rel(rr) ?
				 counterpart->nsec3_nodes : counterpart->nodes;
		zone_tree_del_node(t, node, true);
	}

	return;
}

int changeset_init(changeset_t *ch, const knot_dname_t *apex)
{
	memset(ch, 0, sizeof(changeset_t));

	// Init local changes
	ch->add = zone_contents_new(apex, false);
	if (ch->add == NULL) {
		return KNOT_ENOMEM;
	}
	ch->remove = zone_contents_new(apex, false);
	if (ch->remove == NULL) {
		zone_contents_free(ch->add);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

changeset_t *changeset_new(const knot_dname_t *apex)
{
	changeset_t *ret = malloc(sizeof(changeset_t));
	if (ret == NULL) {
		return NULL;
	}

	if (changeset_init(ret, apex) == KNOT_EOK) {
		return ret;
	} else {
		free(ret);
		return NULL;
	}
}

bool changeset_empty(const changeset_t *ch)
{
	if (ch == NULL) {
		return true;
	}

	if (zone_contents_is_empty(ch->remove) &&
	    zone_contents_is_empty(ch->add)) {
		if (ch->soa_to == NULL) {
			return true;
		}
		if (ch->soa_from != NULL && ch->soa_to != NULL &&
		    knot_rrset_equal(ch->soa_from, ch->soa_to, false)) {
			return true;
		}
	}

	return false;
}

size_t changeset_size(const changeset_t *ch)
{
	if (ch == NULL) {
		return 0;
	}

	changeset_iter_t itt;
	changeset_iter_all(&itt, ch);

	size_t size = 0;
	knot_rrset_t rr = changeset_iter_next(&itt);
	while(!knot_rrset_empty(&rr)) {
		++size;
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	if (!knot_rrset_empty(ch->soa_from)) {
		size += 1;
	}
	if (!knot_rrset_empty(ch->soa_to)) {
		size += 1;
	}

	return size;
}

int changeset_add_addition(changeset_t *ch, const knot_rrset_t *rrset, changeset_flag_t flags)
{
	if (!ch || !rrset) {
		return KNOT_EINVAL;
	}

	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		return handle_soa(&ch->soa_to, rrset);
	}

	knot_rrset_t *rrset_cancelout = NULL;

	/* Check if there's any removal and remove that, then add this
	 * addition anyway. Required to change TTLs. */
	if (flags & CHANGESET_CHECK) {
		/* If we delete the rrset, we need to hold a copy to add it later */
		rrset = knot_rrset_copy(rrset, NULL);
		if (rrset == NULL) {
			return KNOT_ENOMEM;
		}

		check_redundancy(ch->remove, rrset, &rrset_cancelout);
	}

	const knot_rrset_t *to_add = (rrset_cancelout == NULL ? rrset : rrset_cancelout);
	int ret = knot_rrset_empty(to_add) ? KNOT_EOK : add_rr_to_contents(ch->add, to_add);

	if (flags & CHANGESET_CHECK) {
		knot_rrset_free((knot_rrset_t *)rrset, NULL);
	}
	knot_rrset_free(rrset_cancelout, NULL);

	return ret;
}

int changeset_add_removal(changeset_t *ch, const knot_rrset_t *rrset, changeset_flag_t flags)
{
	if (!ch || !rrset) {
		return KNOT_EINVAL;
	}

	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		return handle_soa(&ch->soa_from, rrset);
	}

	knot_rrset_t *rrset_cancelout = NULL;

	/* Check if there's any addition and remove that, then add this
	 * removal anyway. */
	if (flags & CHANGESET_CHECK) {
		/* If we delete the rrset, we need to hold a copy to add it later */
		rrset = knot_rrset_copy(rrset, NULL);
		if (rrset == NULL) {
			return KNOT_ENOMEM;
		}

		check_redundancy(ch->add, rrset, &rrset_cancelout);
	}

	const knot_rrset_t *to_remove = (rrset_cancelout == NULL ? rrset : rrset_cancelout);
	int ret = (knot_rrset_empty(to_remove) || ch->remove == NULL) ? KNOT_EOK : add_rr_to_contents(ch->remove, to_remove);

	if (flags & CHANGESET_CHECK) {
		knot_rrset_free((knot_rrset_t *)rrset, NULL);
	}
	knot_rrset_free(rrset_cancelout, NULL);

	return ret;
}

int changeset_remove_addition(changeset_t *ch, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		if (ch->soa_to != NULL) {
			knot_rrset_free(ch->soa_to, NULL);
			ch->soa_to = NULL;
		}
		return KNOT_EOK;
	}

	zone_node_t *n = NULL;
	return zone_contents_remove_rr(ch->add, rrset, &n);
}

int changeset_remove_removal(changeset_t *ch, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		if (ch->soa_from != NULL) {
			knot_rrset_free(ch->soa_from, NULL);
			ch->soa_from = NULL;
		}
		return KNOT_EOK;
	}

	zone_node_t *n = NULL;
	return zone_contents_remove_rr(ch->remove, rrset, &n);
}

int changeset_merge(changeset_t *ch1, const changeset_t *ch2, int flags)
{
	changeset_iter_t itt;
	changeset_iter_rem(&itt, ch2);

	knot_rrset_t rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		int ret = changeset_add_removal(ch1, &rrset, CHANGESET_CHECK | flags);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rrset = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	changeset_iter_add(&itt, ch2);

	rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		int ret = changeset_add_addition(ch1, &rrset, CHANGESET_CHECK | flags);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rrset = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	// Use soa_to and serial from the second changeset
	// soa_to from the first changeset is redundant, delete it
	if (ch2->soa_to == NULL && ch2->soa_from == NULL) {
		// but not if ch2 has no soa change
		return KNOT_EOK;
	}
	knot_rrset_t *soa_copy = knot_rrset_copy(ch2->soa_to, NULL);
	if (soa_copy == NULL && ch2->soa_to) {
		return KNOT_ENOMEM;
	}
	knot_rrset_free(ch1->soa_to, NULL);
	ch1->soa_to = soa_copy;

	return KNOT_EOK;
}

uint32_t changeset_from(const changeset_t *ch)
{
	return ch->soa_from == NULL ? 0 : knot_soa_serial(ch->soa_from->rrs.rdata);
}

uint32_t changeset_to(const changeset_t *ch)
{
	return ch->soa_to == NULL ? 0 : knot_soa_serial(ch->soa_to->rrs.rdata);
}

bool changeset_differs_just_serial(const changeset_t *ch)
{
	if (ch == NULL || ch->soa_from == NULL || ch->soa_to == NULL) {
		return false;
	}

	knot_rrset_t *soa_to_cpy = knot_rrset_copy(ch->soa_to, NULL);
	knot_soa_serial_set(soa_to_cpy->rrs.rdata, knot_soa_serial(ch->soa_from->rrs.rdata));

	bool ret = knot_rrset_equal(ch->soa_from, soa_to_cpy, true);
	knot_rrset_free(soa_to_cpy, NULL);

	changeset_iter_t itt;
	changeset_iter_all(&itt, ch);

	knot_rrset_t rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset) && ret) {
		if (rrset.type != KNOT_RRTYPE_RRSIG || rrset.rrs.count != 1 ||
		    knot_rrsig_type_covered(rrset.rrs.rdata) != KNOT_RRTYPE_SOA) {
			ret = false;
		}
		rrset = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return ret;
}

void changesets_clear(list_t *chgs)
{
	if (chgs) {
		changeset_t *chg, *nxt;
		WALK_LIST_DELSAFE(chg, nxt, *chgs) {
			changeset_clear(chg);
			rem_node(&chg->n);
		}
		init_list(chgs);
	}
}

void changesets_free(list_t *chgs)
{
	if (chgs) {
		changeset_t *chg, *nxt;
		WALK_LIST_DELSAFE(chg, nxt, *chgs) {
			rem_node(&chg->n);
			changeset_free(chg);
		}
		init_list(chgs);
	}
}

void changeset_clear(changeset_t *ch)
{
	if (ch == NULL) {
		return;
	}

	// Delete RRSets in lists, in case there are any left
	zone_contents_deep_free(ch->add);
	zone_contents_deep_free(ch->remove);
	ch->add = NULL;
	ch->remove = NULL;

	knot_rrset_free(ch->soa_from, NULL);
	knot_rrset_free(ch->soa_to, NULL);
	ch->soa_from = NULL;
	ch->soa_to = NULL;

	// Delete binary data
	free(ch->data);
}

changeset_t *changeset_clone(const changeset_t *ch)
{
	if (ch == NULL) {
		return NULL;
	}

	changeset_t *res = changeset_new(ch->add->apex->owner);
	if (res == NULL) {
		return NULL;
	}

	res->soa_from = knot_rrset_copy(ch->soa_from, NULL);
	res->soa_to = knot_rrset_copy(ch->soa_to, NULL);

	int ret = KNOT_EOK;
	changeset_iter_t itt;

	changeset_iter_rem(&itt, ch);
	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr) && ret == KNOT_EOK) {
		ret = changeset_add_removal(res, &rr, 0);
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	changeset_iter_add(&itt, ch);
	rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr) && ret == KNOT_EOK) {
		ret = changeset_add_addition(res, &rr, 0);
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	if ((ch->soa_from != NULL && res->soa_from == NULL) ||
	    (ch->soa_to != NULL && res->soa_to == NULL) ||
	    ret != KNOT_EOK) {
		changeset_free(res);
		return NULL;
	}

	return res;
}

void changeset_free(changeset_t *ch)
{
	changeset_clear(ch);
	free(ch);
}

int changeset_iter_add(changeset_iter_t *itt, const changeset_t *ch)
{
	return changeset_iter_init(itt, 2, ch->add->nodes, ch->add->nsec3_nodes);
}

int changeset_iter_rem(changeset_iter_t *itt, const changeset_t *ch)
{
	return changeset_iter_init(itt, 2, ch->remove->nodes, ch->remove->nsec3_nodes);
}

int changeset_iter_all(changeset_iter_t *itt, const changeset_t *ch)
{
	return changeset_iter_init(itt, 4, ch->add->nodes, ch->add->nsec3_nodes,
	                           ch->remove->nodes, ch->remove->nsec3_nodes);
}

knot_rrset_t changeset_iter_next(changeset_iter_t *it)
{
	assert(it);

	knot_rrset_t rr;
	while (it->node == NULL || it->node_pos >= it->node->rrset_count) {
		if (it->node != NULL) {
			zone_tree_it_next(&it->it);
		}
		while (zone_tree_it_finished(&it->it)) {
			zone_tree_it_free(&it->it);
			if (--it->n_trees > 0) {
				for (size_t i = 0; i < it->n_trees; i++) {
					it->trees[i] = it->trees[i + 1];
				}
				(void)zone_tree_it_begin(it->trees[0], &it->it);
			} else {
				knot_rrset_init_empty(&rr);
				return rr;
			}
		}
		it->node = zone_tree_it_val(&it->it);
		it->node_pos = 0;
	}
	rr = node_rrset_at(it->node, it->node_pos++);
	assert(!knot_rrset_empty(&rr));
	return rr;
}

void changeset_iter_clear(changeset_iter_t *it)
{
	if (it) {
		zone_tree_it_free(&it->it);
		it->node = NULL;
		it->node_pos = 0;
	}
}

int changeset_walk(const changeset_t *changeset, changeset_walk_callback callback, void *ctx)
{
	changeset_iter_t it;
	int ret = changeset_iter_rem(&it, changeset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		ret = callback(&rrset, false, ctx);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&it);
			return ret;
		}
		rrset = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);

	if (changeset->soa_from != NULL) {
		ret = callback(changeset->soa_from, false, ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	ret = changeset_iter_add(&it, changeset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		ret = callback(&rrset, true, ctx);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&it);
			return ret;
		}
		rrset = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);

	if (changeset->soa_to != NULL) {
		ret = callback(changeset->soa_to, true, ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

void changeset_print(const changeset_t *changeset, FILE *outfile, bool color)
{
	size_t buflen = 1024;
	char *buff = malloc(buflen);

	knot_dump_style_t style = KNOT_DUMP_STYLE_DEFAULT;
	style.now = knot_time();

	style.color = COL_RED(color);
	if (changeset->soa_from != NULL || !zone_contents_is_empty(changeset->remove)) {
		fprintf(outfile, "%s;; Removed%s\n", style.color, COL_RST(color));
	}
	if (changeset->soa_from != NULL && buff != NULL) {
		(void)knot_rrset_txt_dump(changeset->soa_from, &buff, &buflen, &style);
		fprintf(outfile, "%s%s%s", style.color, buff, COL_RST(color));
	}
	(void)zone_dump_text(changeset->remove, outfile, false, style.color);

	style.color = COL_GRN(color);
	if (changeset->soa_to != NULL || !zone_contents_is_empty(changeset->add)) {
		fprintf(outfile, "%s;; Added%s\n", style.color, COL_RST(color));
	}
	if (changeset->soa_to != NULL && buff != NULL) {
		(void)knot_rrset_txt_dump(changeset->soa_to, &buff, &buflen, &style);
		fprintf(outfile, "%s%s%s", style.color, buff, COL_RST(color));
	}
	(void)zone_dump_text(changeset->add, outfile, false, style.color);

	free(buff);
}
