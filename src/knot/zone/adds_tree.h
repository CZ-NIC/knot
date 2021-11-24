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

#pragma once

#include "contrib/qp-trie/trie.h"
#include "knot/zone/contents.h"
#include "knot/dnssec/zone-nsec.h"

typedef trie_t additionals_tree_t;

inline static additionals_tree_t *additionals_tree_new(void) { return trie_create(NULL); }
void additionals_tree_free(additionals_tree_t *a_t);

/*!
 * \brief Foreach additional in all node RRSets, do sth.
 *
 * \note This is not too related to additionals_tree, might be moved.
 *
 * \param node        Zone node with possibly NS, MX, etc rrsets.
 * \param zone_apex   Name of the zone apex.
 * \param cb          Callback to be performed.
 * \param ctx         Arbitrary context for the callback.
 *
 * \return KNOT_E*
 */
typedef int (*zone_node_additionals_cb_t)(const knot_dname_t *additional, void *ctx);
int zone_node_additionals_foreach(const zone_node_t *node, const knot_dname_t *zone_apex,
                                  zone_node_additionals_cb_t cb, void *ctx);

/*!
 * \brief Update additionals tree according to changed RRsets in a zone node.
 *
 * \param a_t         Additionals tree to be updated.
 * \param zone_apex   Zone apex owner.
 * \param old_node    Old state of the node (additionals will be removed).
 * \param new_node    New state of the node (additionals will be added).
 *
 * \return KNOT_E*
 */
int additionals_tree_update_node(additionals_tree_t *a_t, const knot_dname_t *zone_apex,
                                 zone_node_t *old_node, zone_node_t *new_node);

/*!
 * \brief Update additionals tree with NSEC3 according to changed normal nodes.
 *
 * \param a_t         Additionals tree to be updated.
 * \param zone        Zone contents with NSEC3PARAMS etc.
 * \param old_node    Old state of the node.
 * \param new_node    New state of the node.
 *
 * \return KNOT_E*
 */
int additionals_tree_update_nsec3(additionals_tree_t *a_t, const zone_contents_t *zone,
                                  zone_node_t *old_node, zone_node_t *new_node);

/*!
 * \brief Create additionals tree from a zone (by scanning all additionals in zone RRsets).
 *
 * \param a_t    Out: additionals tree to be created (NULL if error).
 * \param zone   Zone contents.
 *
 * \return KNOT_E*
 */
int additionals_tree_from_zone(additionals_tree_t **a_t, const zone_contents_t *zone);

/*!
 * \brief Update additionals tree according to changed RRsets in all nodes in a zone tree.
 *
 * \param a_t          Additionals tree to be updated.
 * \param tree         Zone tree containing updated nodes as bi-nodes.
 * \param zone         Whole zone with some additional info.
 *
 * \return KNOT_E*
 */
int additionals_tree_update_from_binodes(additionals_tree_t *a_t, const zone_tree_t *tree,
                                         const zone_contents_t *zone);

/*!
 * \brief Foreach node that has specified name in its additionals, do sth.
 *
 * \note The node passed to the callback might not be correct part of bi-node!
 *
 * \param a_t    Additionals reverse tree.
 * \param name   Name to be looked up in the additionals.
 * \param cb     Callback to be called.
 * \param ctx    Arbitrary context for the callback.
 *
 * \return KNOT_E*
 */
typedef int (*node_apply_cb_t)(zone_node_t *node, void *ctx);
int additionals_reverse_apply(additionals_tree_t *a_t, const knot_dname_t *name,
                              node_apply_cb_t cb, void *ctx);

/*!
 * \brief Call additionals_reverse_apply() for every name in specified tree.
 *
 * \param a_t    Additionals reverse tree.
 * \param tree   Zone tree with names to be looked up in additionals.
 * \param cb     Callback to be called for each affected node.
 * \param ctx    Arbitrary context for the callback.
 *
 * \return KNOT_E*
 */
int additionals_reverse_apply_multi(additionals_tree_t *a_t, const zone_tree_t *tree,
                                    node_apply_cb_t cb, void *ctx);

