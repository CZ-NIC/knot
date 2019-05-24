/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/measure.h"

measure_t knot_measure_init(bool measure_whole, bool measure_diff)
{
	assert(!measure_whole || !measure_diff);
	measure_t m = { 0 };
	if (measure_whole) {
		m.how_size = MEASURE_SIZE_WHOLE;
		m.how_ttl = MEASURE_TTL_WHOLE;
	}
	if (measure_diff) {
		m.how_size = MEASURE_SIZE_DIFF;
		m.how_ttl = MEASURE_TTL_DIFF;
	}
	return m;
}

bool knot_measure_node(zone_node_t *node, measure_t *m)
{
	if (m->how_size == MEASURE_SIZE_NONE && (m->how_ttl == MEASURE_TTL_NONE ||
	      (m->how_ttl == MEASURE_TTL_LIMIT && m->max_ttl >= m->limit_max_ttl))) {
		return false;
	}

	int rrset_count = node->rrset_count;
	for (int i = 0; i < rrset_count; i++) {
		if (m->how_size != MEASURE_SIZE_NONE) {
			knot_rrset_t rrset = node_rrset_at(node, i);
			m->zone_size += knot_rrset_size(&rrset);
		}
		if (m->how_ttl != MEASURE_TTL_NONE) {
			m->max_ttl = MAX(m->max_ttl, node->rrs[i].ttl);
		}
	}

	if (m->how_size != MEASURE_SIZE_DIFF && m->how_ttl != MEASURE_TTL_DIFF) {
		return true;
	}

	node = binode_counterpart(node);
	rrset_count = node->rrset_count;
	for (int i = 0; i < rrset_count; i++) {
		if (m->how_size == MEASURE_SIZE_DIFF) {
			knot_rrset_t rrset = node_rrset_at(node, i);
			m->zone_size -= knot_rrset_size(&rrset);
		}
		if (m->how_ttl == MEASURE_TTL_DIFF) {
			m->rem_max_ttl = MAX(m->rem_max_ttl, node->rrs[i].ttl);
		}
	}

	return true;
}

static uint32_t re_measure_max_ttl(zone_contents_t *zone, uint32_t limit)
{
	measure_t m = {0 };
	m.how_ttl = MEASURE_TTL_LIMIT;
	m.limit_max_ttl = limit;

	zone_tree_it_t it = { 0 };
	int ret = zone_tree_it_double_begin(zone->nodes, zone->nsec3_nodes, &it);
	if (ret != KNOT_EOK) {
		return limit;
	}

	while (!zone_tree_it_finished(&it) && knot_measure_node(zone_tree_it_val(&it), &m)) {
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);

	return m.max_ttl;
}

void knot_measure_finish_zone(measure_t *m, zone_contents_t *zone)
{
	assert(m->how_size == MEASURE_SIZE_WHOLE || m->how_size == MEASURE_SIZE_NONE);
	assert(m->how_ttl == MEASURE_TTL_WHOLE || m->how_ttl == MEASURE_TTL_NONE);
	if (m->how_size == MEASURE_SIZE_WHOLE) {
		zone->size = m->zone_size;
	}
	if (m->how_ttl == MEASURE_TTL_WHOLE) {
		zone->max_ttl = m->max_ttl;
	}
}

void knot_measure_finish_update(measure_t *m, zone_update_t *update)
{
	switch (m->how_size) {
	case MEASURE_SIZE_NONE:
		break;
	case MEASURE_SIZE_WHOLE:
		update->new_cont->size = m->zone_size;
		break;
	case MEASURE_SIZE_DIFF:
		update->new_cont->size = update->zone->contents->size + m->zone_size;
		break;
	}

	switch (m->how_ttl) {
	case MEASURE_TTL_NONE:
		break;
	case MEASURE_TTL_WHOLE:
	case MEASURE_TTL_LIMIT:
		update->new_cont->max_ttl = m->max_ttl;
		break;
	case MEASURE_TTL_DIFF:
		if (m->max_ttl >= update->zone->contents->max_ttl) {
			update->new_cont->max_ttl = m->max_ttl;
		} else if (update->zone->contents->max_ttl > m->rem_max_ttl) {
			update->new_cont->max_ttl = update->zone->contents->max_ttl;
		} else {
			update->new_cont->max_ttl = re_measure_max_ttl(update->new_cont, update->zone->contents->max_ttl);
		}
		break;
	}
}
