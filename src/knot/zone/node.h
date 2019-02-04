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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

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
	struct zone_node *nsec3_node; /*! NSEC3 node corresponding to this node. */
	uint8_t *nsec3_wildcard_hash;
	uint32_t children; /*!< Count of children nodes in DNS hierarchy. */
	uint16_t rrset_count; /*!< Number of RRSets stored in the node. */
	uint8_t flags; /*!< \ref node_flags enum. */
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
	/*! \brief Node is empty and will be deleted after update. */
	NODE_FLAGS_EMPTY =           1 << 3,
	/*! \brief Node has a wildcard child. */
	NODE_FLAGS_WILDCARD_CHILD =  1 << 4,
	/*! \brief Is this NSEC3 node compatible with zone's NSEC3PARAMS ? */
	NODE_FLAGS_IN_NSEC3_CHAIN =  1 << 5,
};

/*!
 * \brief Clears additional structure.
 *
 * \param additional  Additional to clear.
 */
void additional_clear(additional_t *additional);

/*!
 * \brief Creates and initializes new node structure.
 *
 * \param owner  Node's owner, will be duplicated.
 * \param mm     Memory context to use.
 *
 * \return Newly created node or NULL if an error occurred.
 */
zone_node_t *node_new(const knot_dname_t *owner, knot_mm_t *mm);

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
 * \brief Creates a shallow copy of node structure, RR data are shared.
 *
 * \param src  Source of the copy.
 * \param mm   Memory context to use.
 *
 * \return Copied node if success, NULL otherwise.
 */
zone_node_t *node_shallow_copy(const zone_node_t *src, knot_mm_t *mm);

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
 * \brief Sets the parent of the node. Also adjusts children count of parent.
 *
 * \param node Node to set the parent of.
 * \param parent Parent to set to the node.
 */
void node_set_parent(zone_node_t *node, zone_node_t *parent);

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
 * \brief Compute node size.
 *
 * \param node   Node in question.
 * \param size   In/out: node size will be added to this value.
 */
void node_size(const zone_node_t *node, size_t *size);

/*!
 * \brief Compute node maximum TTL.
 *
 * \param node   Node in question.
 * \param size   In/out: this value will be maximalized with max TTL of node rrsets.
 */
void node_max_ttl(const zone_node_t *node, uint32_t *max);
