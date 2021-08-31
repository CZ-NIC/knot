/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/rdataset.h"

struct rr_data;

/*!
 * \brief Structure representing one node in a domain name tree, i.e. one domain
 *        name in a zone.
 */
typedef struct zone_node {
	knot_dname_t *owner; /*!< Domain name being the owner of this node. */
	struct zone_node *parent; /*!< Parent node in the name hierarchy. */

	/*! \brief Array with data of RRSets belonging to this node. */
	struct rr_data *rrs;

	/*!
	 * \brief Previous node in canonical order. Only authoritative
	 *        nodes or delegation points are referenced by this.
	 */
	struct zone_node *prev;
	union {
		knot_dname_t *nsec3_hash; /*! Name of the NSEC3 corresponding to this node. */
		struct zone_node *nsec3_node; /*! NSEC3 node corresponding to this node.
		\warning This always points to first part of that bi-node!
		assert(!(node->nsec3_node & NODE_FLAGS_SECOND)); */
	};
	knot_dname_t *nsec3_wildcard_name; /*! Name of NSEC3 node proving wildcard nonexistence. */
	uint32_t children; /*!< Count of children nodes in DNS hierarchy. */
	uint16_t rrset_count; /*!< Number of RRSets stored in the node. */
	uint16_t flags; /*!< \ref node_flags enum. */
} zone_node_t;

/*!< \brief Glue node context. */
typedef struct {
	const zone_node_t *node; /*!< Glue node. */
	uint16_t ns_pos; /*!< Corresponding NS record position (for compression). */
	bool optional; /*!< Optional glue indicator. */
} glue_t;

/*!< \brief Additional data. */
typedef struct {
	glue_t *glues; /*!< Glue data. */
	uint16_t count; /*!< Number of glue nodes. */
} additional_t;

/*!< \brief Structure storing RR data. */
struct rr_data {
	uint32_t ttl; /*!< RRSet TTL. */
	uint16_t type; /*!< RR type of data. */
	knot_rdataset_t rrs; /*!< Data of given type. */
	additional_t *additional; /*!< Additional nodes with glues. */
};

/*! \brief Flags used to mark nodes with some property. */
enum node_flags {
	/*! \brief Node is authoritative, default. */
	NODE_FLAGS_AUTH =            0 << 0,
	/*! \brief Node is a delegation point (i.e. marking a zone cut). */
	NODE_FLAGS_DELEG =           1 << 0,
	/*! \brief Node is not authoritative (i.e. below a zone cut). */
	NODE_FLAGS_NONAUTH =         1 << 1,
	/*! \brief RRSIGs in node have been cryptographically validated by Knot. */
	NODE_FLAGS_RRSIGS_VALID =    1 << 2,
	/*! \brief Node is empty and will be deleted after update. */
	NODE_FLAGS_EMPTY =           1 << 3,
	/*! \brief Node has a wildcard child. */
	NODE_FLAGS_WILDCARD_CHILD =  1 << 4,
	/*! \brief Is this NSEC3 node compatible with zone's NSEC3PARAMS ? */
	NODE_FLAGS_IN_NSEC3_CHAIN =  1 << 5,
	/*! \brief Node is the zone Apex. */
	NODE_FLAGS_APEX =            1 << 6,
	/*! \brief The nsec3_node pointer is valid and and nsec3_hash pointer invalid. */
	NODE_FLAGS_NSEC3_NODE =      1 << 7,
	/*! \brief Is this i bi-node? */
	NODE_FLAGS_BINODE =          1 << 8, // this value shall be fixed
	/*! \brief Is this the second half of bi-node? */
	NODE_FLAGS_SECOND =          1 << 9, // this value shall be fixed
	/*! \brief The node shall be deleted. It's just not because it's a bi-node and the counterpart still exists. */
	NODE_FLAGS_DELETED =         1 << 10,
	/*! \brief The node or some node in subtree has some authoritative data in it (possibly also DS at deleg). */
	NODE_FLAGS_SUBTREE_AUTH =    1 << 11,
	/*! \brief The node or some node in subtree has any data in it, possibly just insec deleg. */
	NODE_FLAGS_SUBTREE_DATA =    1 << 12,
};

typedef void (*node_addrem_cb)(zone_node_t *, void *);
typedef zone_node_t *(*node_new_cb)(const knot_dname_t *, void *);

/*!
 * \brief Clears additional structure.
 *
 * \param additional  Additional to clear.
 */
void additional_clear(additional_t *additional);

/*!
 * \brief Compares additional structures on equivalency.
 */
bool additional_equal(additional_t *a, additional_t *b);

/*!
 * \brief Creates and initializes new node structure.
 *
 * \param owner  Node's owner, will be duplicated.
 * \param binode Create bi-node.
 * \param second The second part of the bi-node shall be used now.
 * \param mm     Memory context to use.
 *
 * \return Newly created node or NULL if an error occurred.
 */
zone_node_t *node_new(const knot_dname_t *owner, bool binode, bool second, knot_mm_t *mm);

/*!
 * \brief Synchronize contents of both binode's nodes.
 *
 * \param node           Pointer to either of nodes in a binode.
 * \param free_deleted   When the unified node has DELETED flag, free it afterwards.
 * \param mm             Memory context.
 */
void binode_unify(zone_node_t *node, bool free_deleted, knot_mm_t *mm);

/*!
 * \brief This must be called before any change to either of the bi-node's node's rdatasets.
 */
int binode_prepare_change(zone_node_t *node, knot_mm_t *mm);

/*!
 * \brief Get the correct node of a binode.
 *
 * \param node     Pointer to either of nodes in a binode.
 * \param second   Get the second node (first otherwise).
 *
 * \return Pointer to correct node.
 */
inline static zone_node_t *binode_node(zone_node_t *node, bool second)
{
	if (unlikely(node == NULL || !(node->flags & NODE_FLAGS_BINODE))) {
		assert(node == NULL || !(node->flags & NODE_FLAGS_SECOND));
		return node;
	}
	return node + (second - (int)((node->flags & NODE_FLAGS_SECOND) >> 9));
}

inline static zone_node_t *binode_first(zone_node_t *node)
{
	return binode_node(node, false);
}

inline static zone_node_t *binode_node_as(zone_node_t *node, const zone_node_t *as)
{
	assert(node == NULL || (as->flags & NODE_FLAGS_BINODE) == (node->flags & NODE_FLAGS_BINODE));
	return binode_node(node, (as->flags & NODE_FLAGS_SECOND));
}

/*!
 * \brief Return the other node from a bi-node.
 *
 * \param node   A node in a bi-node.
 *
 * \return The counterpart node in the same bi-node.
 */
zone_node_t *binode_counterpart(zone_node_t *node);

/*!
 * \brief Return true if the rdataset of specified type is shared (shallow-copied) among both parts of bi-node.
 */
bool binode_rdata_shared(zone_node_t *node, uint16_t type);

/*!
 * \brief Return true if the additionals to rdataset of specified type are shared among both parts of bi-node.
 */
bool binode_additional_shared(zone_node_t *node, uint16_t type);

/*!
 * \brief Return true if the additionals are unchanged between two nodes (usually a bi-node).
 */
bool binode_additionals_unchanged(zone_node_t *node, zone_node_t *counterpart);

/*!
 * \brief Destroys allocated data within the node
 *        structure, but not the node itself.
 *
 * \param node  Node that contains data to be destroyed.
 * \param mm    Memory context to use.
 */
void node_free_rrsets(zone_node_t *node, knot_mm_t *mm);

/*!
 * \brief Destroys the node structure.
 *
 * Does not destroy the data within the node.
 *
 * \param node  Node to be destroyed.
 * \param mm    Memory context to use.
 */
void node_free(zone_node_t *node, knot_mm_t *mm);

/*!
 * \brief Adds an RRSet to the node. All data are copied. Owner and class are
 *        not used at all.
 *
 * \param node     Node to add the RRSet to.
 * \param rrset    RRSet to add.
 * \param mm       Memory context to use.
 *
 * \return KNOT_E*
 * \retval KNOT_ETTL  RRSet TTL was updated.
 */
int node_add_rrset(zone_node_t *node, const knot_rrset_t *rrset, knot_mm_t *mm);

/*!
 * \brief Removes data for given RR type from node.
 *
 * \param node  Node we want to delete from.
 * \param type  RR type to delete.
 */
void node_remove_rdataset(zone_node_t *node, uint16_t type);

/*!
 * \brief Remove all RRs from RRSet from the node.
 *
 * \param node    Node to remove from.
 * \param rrset   RRSet with RRs to be removed.
 * \param mm      Memory context.
 *
 * \return KNOT_E*
 */
int node_remove_rrset(zone_node_t *node, const knot_rrset_t *rrset, knot_mm_t *mm);

/*!
 * \brief Returns the RRSet of the given type from the node. RRSet is allocated.
 *
 * \param node  Node to get the RRSet from.
 * \param type  RR type of the RRSet to retrieve.
 *
 * \return RRSet from node \a node having type \a type, or NULL if no such
 *         RRSet exists in this node.
 */
knot_rrset_t *node_create_rrset(const zone_node_t *node, uint16_t type);

/*!
 * \brief Gets rdata set structure of given type from node.
 *
 * \param node  Node to get data from.
 * \param type  RR type of data to get.
 *
 * \return Pointer to data if found, NULL otherwise.
 */
knot_rdataset_t *node_rdataset(const zone_node_t *node, uint16_t type);

/*!
 * \brief Returns parent node (fixing bi-node issue) of given node.
 */
inline static zone_node_t *node_parent(const zone_node_t *node)
{
	return binode_node_as(node->parent, node);
}

/*!
 * \brief Returns previous (lexicographically in same zone tree) node (fixing bi-node issue) of given node.
 */
inline static zone_node_t *node_prev(const zone_node_t *node)
{
	return binode_node_as(node->prev, node);
}

/*!
 * \brief Return node referenced by a glue.
 *
 * \param glue                Glue in question.
 * \param another_zone_node   Another node from the same zone.
 *
 * \return Glue node.
 */
inline static const zone_node_t *glue_node(const glue_t *glue, const zone_node_t *another_zone_node)
{
	return binode_node_as((zone_node_t *)glue->node, another_zone_node);
}

/*!
 * \brief Add a flag to this node and all (grand-)parents until the flag is present.
 */
inline static void node_set_flag_hierarch(zone_node_t *node, uint16_t fl)
{
	for (zone_node_t *i = node; i != NULL && (i->flags & fl) != fl; i = node_parent(i)) {
		i->flags |= fl;
	}
}

/*!
 * \brief Checks whether node contains any RRSIG for given type.
 *
 * \param node  Node to check in.
 * \param type  Type to check for.
 *
 * \return True/False.
 */
bool node_rrtype_is_signed(const zone_node_t *node, uint16_t type);

/*!
 * \brief Checks whether node contains RRSet for given type.
 *
 * \param node  Node to check in.
 * \param type  Type to check for.
 *
 * \return True/False.
 */
inline static bool node_rrtype_exists(const zone_node_t *node, uint16_t type)
{
	return node_rdataset(node, type) != NULL;
}

/*!
 * \brief Checks whether node is empty. Node is empty when NULL or when no
 *        RRSets are in it.
 *
 * \param node  Node to check in.
 *
 * \return True/False.
 */
inline static bool node_empty(const zone_node_t *node)
{
	return node == NULL || node->rrset_count == 0;
}

/*!
 * \brief Check whether two nodes have equal set of rrtypes.
 *
 * \param a  A node.
 * \param b  Another node.
 *
 * \return True/False.
 */
bool node_bitmap_equal(const zone_node_t *a, const zone_node_t *b);

/*!
 * \brief Returns RRSet structure initialized with data from node.
 *
 * \param node   Node containing RRSet.
 * \param type   RRSet type we want to get.
 *
 * \return RRSet structure with wanted type, or empty RRSet.
 */
static inline knot_rrset_t node_rrset(const zone_node_t *node, uint16_t type)
{
	knot_rrset_t rrset;
	for (uint16_t i = 0; node && i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			struct rr_data *rr_data = &node->rrs[i];
			knot_rrset_init(&rrset, node->owner, type, KNOT_CLASS_IN,
			                rr_data->ttl);
			rrset.rrs = rr_data->rrs;
			rrset.additional = rr_data->additional;
			return rrset;
		}
	}
	knot_rrset_init_empty(&rrset);
	return rrset;
}

/*!
 * \brief Returns RRSet structure initialized with data from node at position
 *        equal to \a pos.
 *
 * \param node  Node containing RRSet.
 * \param pos   RRSet position we want to get.
 *
 * \return RRSet structure with data from wanted position, or empty RRSet.
 */
static inline knot_rrset_t node_rrset_at(const zone_node_t *node, size_t pos)
{
	knot_rrset_t rrset;
	if (node == NULL || pos >= node->rrset_count) {
		knot_rrset_init_empty(&rrset);
		return rrset;
	}

	struct rr_data *rr_data = &node->rrs[pos];
	knot_rrset_init(&rrset, node->owner, rr_data->type, KNOT_CLASS_IN,
	                rr_data->ttl);
	rrset.rrs = rr_data->rrs;
	rrset.additional = rr_data->additional;
	return rrset;
}

/*!
 * \brief Return the relevant NSEC3 node (if specified by adjusting), or NULL.
 */
static inline zone_node_t *node_nsec3_get(const zone_node_t *node)
{
	if (!(node->flags & NODE_FLAGS_NSEC3_NODE) || node->nsec3_node == NULL) {
		return NULL;
	} else {
		return binode_node_as(node->nsec3_node, node);
	}
}
