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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>

#include "knot/updates/changesets.h"
#include "knot/updates/apply.h"
#include "libknot/libknot.h"
#include "knot/zone/zone-dump.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"

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
	zone_node_t *n = NULL;
	int ret = zone_contents_add_rr(z, rrset, &n);
	UNUSED(n);

	// We don't care of TTLs.
	return ret == KNOT_ETTL ? KNOT_EOK : ret;
}

/*! \brief Cleans up trie iterations. */
static void cleanup_iter_list(list_t *l)
{
	ptrnode_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		trie_it_t *it = (trie_it_t *)n->d;
		trie_it_free(it);
		rem_node(&n->n);
		free(n);
	}
	init_list(l);
}

/*! \brief Inits changeset iterator with given tries. */
static int changeset_iter_init(changeset_iter_t *ch_it, size_t tries, ...)
{
	memset(ch_it, 0, sizeof(*ch_it));
	init_list(&ch_it->iters);

	va_list args;
	va_start(args, tries);

	for (size_t i = 0; i < tries; ++i) {
		trie_t *t = va_arg(args, trie_t *);
		if (t == NULL) {
			continue;
		}

		trie_it_t *it = trie_it_begin(t);
		if (it == NULL) {
			cleanup_iter_list(&ch_it->iters);
			va_end(args);
			return KNOT_ENOMEM;
		}

		if (ptrlist_add(&ch_it->iters, it, NULL) == NULL) {
			cleanup_iter_list(&ch_it->iters);
			va_end(args);
			return KNOT_ENOMEM;
		}
	}

	va_end(args);

	return KNOT_EOK;
}

/*! \brief Gets next node from trie iterators. */
static void iter_next_node(changeset_iter_t *ch_it, trie_it_t *t_it)
{
	assert(!trie_it_finished(t_it));
	// Get next node, but not for the very first call.
	if (ch_it->node) {
		trie_it_next(t_it);
	}
	if (trie_it_finished(t_it)) {
		ch_it->node = NULL;
		return;
	}

	ch_it->node = (zone_node_t *)*trie_it_val(t_it);
	assert(ch_it->node);
	while (ch_it->node && ch_it->node->rrset_count == 0) {
		// Skip empty non-terminals.
		trie_it_next(t_it);
		if (trie_it_finished(t_it)) {
			ch_it->node = NULL;
		} else {
			ch_it->node = (zone_node_t *)*trie_it_val(t_it);
			assert(ch_it->node);
		}
	}

	ch_it->node_pos = 0;
}

/*! \brief Gets next RRSet from trie iterators. */
static knot_rrset_t get_next_rr(changeset_iter_t *ch_it, trie_it_t *t_it)
{
	if (ch_it->node == NULL || ch_it->node_pos == ch_it->node->rrset_count) {
		iter_next_node(ch_it, t_it);
		if (ch_it->node == NULL) {
			assert(trie_it_finished(t_it));
			knot_rrset_t rr;
			knot_rrset_init_empty(&rr);
			return rr;
		}
	}

	return node_rrset_at(ch_it->node, ch_it->node_pos++);
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

	// Subtract the data from node's RRSet.
	knot_rdataset_t *rrs = node_rdataset(node, rr->type);
	uint32_t rrs_ttl = node_rrset(node, rr->type).ttl;

	if (fixed_rr != NULL && *fixed_rr != NULL && (*fixed_rr)->ttl == rrs_ttl) {
		int ret = knot_rdataset_subtract(&(*fixed_rr)->rrs, rrs, NULL);
		if (ret != KNOT_EOK) {
			return;
		}
	}

	if (rr->ttl == rrs_ttl) {
		int ret = knot_rdataset_subtract(rrs, &rr->rrs, NULL);
		if (ret != KNOT_EOK) {
			return;
		}
	}

	if (knot_rdataset_size(rrs) == 0) {
		// Remove empty type.
		node_remove_rdataset(node, rr->type);

		if (node->rrset_count == 0 && node != counterpart->apex) {
			// Remove empty node.
			zone_tree_t *t = knot_rrset_is_nsec3rel(rr) ?
			                 counterpart->nsec3_nodes : counterpart->nodes;
			zone_tree_delete_empty(t, node);
		}
	}

	return;
}

int changeset_init(changeset_t *ch, const knot_dname_t *apex)
{
	memset(ch, 0, sizeof(changeset_t));

	// Init local changes
	ch->add = zone_contents_new(apex);
	if (ch->add == NULL) {
		return KNOT_ENOMEM;
	}
	ch->remove = zone_contents_new(apex);
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
	if (ch == NULL || ch->add == NULL || ch->remove == NULL) {
		return true;
	}

	if (ch->soa_to) {
		return false;
	}

	changeset_iter_t itt;
	changeset_iter_all(&itt, ch);

	knot_rrset_t rr = changeset_iter_next(&itt);
	changeset_iter_clear(&itt);

	return knot_rrset_empty(&rr);
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

		check_redundancy(ch->remove, rrset,
				 ((flags & CHANGESET_CHECK_CANCELOUT) ? &rrset_cancelout : NULL));
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

		check_redundancy(ch->add, rrset,
				 ((flags & CHANGESET_CHECK_CANCELOUT) ? &rrset_cancelout : NULL));
	}

	const knot_rrset_t *to_remove = (rrset_cancelout == NULL ? rrset : rrset_cancelout);
	int ret = knot_rrset_empty(to_remove) ? KNOT_EOK : add_rr_to_contents(ch->remove, to_remove);

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

typedef struct {
	const zone_contents_t *zone;
	changeset_t *fixing;
	knot_mm_t *mm;
} preapply_fix_ctx;

static int preapply_fix_rrset(const knot_rrset_t *apply, bool adding, void *data)
{
	preapply_fix_ctx *ctx  = (preapply_fix_ctx *)data;
	const zone_node_t *znode = zone_contents_find_node(ctx->zone, apply->owner);
	const knot_rdataset_t *zrdataset = node_rdataset(znode, apply->type);
	if (adding && zrdataset == NULL) {
		return KNOT_EOK;
	}

	knot_rrset_t *fixrrset;
	if (adding) {
		fixrrset = knot_rrset_new(apply->owner, apply->type, apply->rclass,
		                          apply->ttl, ctx->mm);
	} else {
		fixrrset = knot_rrset_copy(apply, ctx->mm);
	}
	if (fixrrset == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = KNOT_EOK;
	if (adding) {
		ret = knot_rdataset_intersect(zrdataset, &apply->rrs, &fixrrset->rrs, ctx->mm);
	} else {
		uint32_t zrrset_ttl = node_rrset(znode, apply->type).ttl;
		if (zrdataset != NULL && fixrrset->ttl == zrrset_ttl) {
			ret = knot_rdataset_subtract(&fixrrset->rrs, zrdataset, ctx->mm);
		}
	}
	if (ret == KNOT_EOK && !knot_rrset_empty(fixrrset)) {
		if (adding) {
			ret = changeset_add_removal(ctx->fixing, fixrrset, 0);
		} else {
			ret = changeset_add_addition(ctx->fixing, fixrrset, 0);
		}
	}

	knot_rrset_free(fixrrset, ctx->mm);
	return ret;
}

static int subtract_callback(const knot_rrset_t *rrset, bool addition, void *subtractfrom)
{
	changeset_t *chsf = (changeset_t *)subtractfrom;
	if (addition) {
		return changeset_remove_removal(chsf, rrset);
	} else {
		return changeset_remove_addition(chsf, rrset);
	}
}

static int subtract(changeset_t *from, const changeset_t *what)
{
	return changeset_walk(what, subtract_callback, (void *)from);
}

int changeset_preapply_fix(const zone_contents_t *zone, changeset_t *ch)
{
	if (zone == NULL || ch == NULL) {
		return KNOT_EINVAL;
	}

	changeset_t fixing;
	int ret = changeset_init(&fixing, zone->apex->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	preapply_fix_ctx ctx = { .zone = zone, .fixing = &fixing, .mm = NULL };
	ret = changeset_walk(ch, preapply_fix_rrset, (void *)&ctx);
	if (ret == KNOT_EOK) {
		ret = subtract(ch, &fixing);
	}
	changeset_clear(&fixing);
	return ret;
}

int changeset_cancelout(changeset_t *ch)
{
	if (ch == NULL) {
		return KNOT_EINVAL;
	}

	changeset_t fixing;
	int ret = changeset_init(&fixing, ch->add->apex->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	preapply_fix_ctx ctx = { .zone = ch->remove, .fixing = &fixing, .mm = NULL };
	ret = changeset_walk(ch, preapply_fix_rrset, (void *)&ctx);
	if (ret == KNOT_EOK) {
		assert(zone_contents_is_empty(fixing.add));
		zone_contents_t *fixing_add_bck = fixing.add;
		fixing.add = fixing.remove;
		ret = subtract(ch, &fixing);
		fixing.add = fixing_add_bck;
	}
	changeset_clear(&fixing);
	return ret;
}

int changeset_to_contents(changeset_t *ch, zone_contents_t **out)
{
	assert(ch->soa_from == NULL);
	assert(zone_contents_is_empty(ch->remove));
	assert(out != NULL);

	*out = ch->add;
	int ret = add_rr_to_contents(*out, ch->soa_to);
	knot_rrset_free(ch->soa_to, NULL);
	if (ret != KNOT_EOK) {
		zone_contents_deep_free(*out);
	}

	zone_contents_deep_free(ch->remove);
	free(ch->data);
	free(ch);
	return ret;
}

changeset_t *changeset_from_contents(const zone_contents_t *contents)
{
	zone_contents_t *copy = NULL;
	if (zone_contents_shallow_copy(contents, &copy) != KNOT_EOK) {
		return NULL;
	}

	changeset_t *res = changeset_new(copy->apex->owner);

	knot_rrset_t soa_rr = node_rrset(copy->apex, KNOT_RRTYPE_SOA);;
	res->soa_to = knot_rrset_copy(&soa_rr, NULL);

	node_remove_rdataset(copy->apex, KNOT_RRTYPE_SOA);

	zone_contents_deep_free(res->add);
	res->add = copy;
	return res;
}

void changeset_from_contents_free(changeset_t *ch)
{
	assert(ch);
	assert(ch->soa_from == NULL);
	assert(zone_contents_is_empty(ch->remove));

	update_free_zone(ch->add);

	zone_contents_deep_free(ch->remove);
	knot_rrset_free(ch->soa_from, NULL);
	knot_rrset_free(ch->soa_to, NULL);
	free(ch->data);
	free(ch);
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
	ptrnode_t *n = NULL;
	knot_rrset_t rr;
	knot_rrset_init_empty(&rr);
	WALK_LIST(n, it->iters) {
		trie_it_t *t_it = (trie_it_t *)n->d;
		if (trie_it_finished(t_it)) {
			continue;
		}

		rr = get_next_rr(it, t_it);
		if (!knot_rrset_empty(&rr)) {
			// Got valid RRSet.
			return rr;
		}
	}

	return rr;
}

void changeset_iter_clear(changeset_iter_t *it)
{
	if (it) {
		cleanup_iter_list(&it->iters);
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

	return KNOT_EOK;
}

void changeset_print(const changeset_t *changeset, FILE *outfile, bool color)
{
	const char * RED = "\x1B[31m", * GRN = "\x1B[32m", * RESET = "\x1B[0m";
	size_t buflen = 1024;
	char *buff = malloc(buflen);

	if (changeset->soa_from != NULL || !zone_contents_is_empty(changeset->remove)) {
		fprintf(outfile, "%s;;Removed\n", color ? RED : "");
	}
	if (changeset->soa_from != NULL && buff != NULL) {
		(void)knot_rrset_txt_dump(changeset->soa_from, &buff, &buflen, &KNOT_DUMP_STYLE_DEFAULT);
		fprintf(outfile, "%s", buff);
	}
	(void)zone_dump_text(changeset->remove, outfile, false);

	if (changeset->soa_to != NULL || !zone_contents_is_empty(changeset->add)) {
		fprintf(outfile, "%s;;Added\n", color ? GRN : "");
	}
	if (changeset->soa_to != NULL && buff != NULL) {
		(void)knot_rrset_txt_dump(changeset->soa_to, &buff, &buflen, &KNOT_DUMP_STYLE_DEFAULT);
		fprintf(outfile, "%s", buff);
	}
	(void)zone_dump_text(changeset->add, outfile, false);

	if (color) {
		printf("%s", RESET);
	}
	free(buff);
}
