/*!
 * \file node.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure representing one node in domain name tree and API for
 *        manipulating it.
 *
 * \addtogroup libknot
 * @{
 */
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

#ifndef _KNOT_NODE_H_
#define _KNOT_NODE_H_

#include "common/descriptor.h"
#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/rdataset.h"

struct rr_data;

/*!
 * \brief Structure representing one node in a domain name tree, i.e. one domain
 *        name in a zone.
 *
 * RRSets are stored in an array.
 */
struct knot_node {
	knot_dname_t *owner; /*!< Domain name being the owner of this node. */
	struct knot_node *parent; /*!< Parent node in the name hierarchy. */

	/*! \brief Type-ordered array of RRSets belonging to this node. */
	struct rr_data *rrs;

	/*!
	 * \brief Previous node in canonical order.
	 *
	 * Only authoritative nodes or delegation points are referenced by this,
	 * as only they may contain NSEC records needed for authenticating
	 * negative answers.
	 */
	struct knot_node *prev;

	/*!
	 * \brief NSEC3 node corresponding to this node.
	 *
	 * Such NSEC3 node has owner in form of the hashed domain name of this
	 * node prepended as a single label to the zone name.
	 */
	struct knot_node *nsec3_node;

	unsigned int children;

	uint16_t rrset_count; /*!< Number of RRSets stored in the node. */

	/*!
	 * \brief Various flags.
	 *
	 * \ref knot_node_flags_t
	 */
	uint8_t flags;
};

typedef struct knot_node knot_node_t;

/*!< \brief Structure storing RR data. */
struct rr_data {
	uint16_t type; /*!< \brief RR type of data. */
	knot_rdataset_t rrs; /*!< \brief Data of given type. */
	knot_node_t **additional; /*!< \brief Additional nodes with glues. */
};

/*----------------------------------------------------------------------------*/
/*! \brief Flags used to mark nodes with some property. */
typedef enum {
	/*! \brief Empty flag initializer. */
	KNOT_NODE_FLAGS_NULL =            0 << 0,
	/*! \brief Node is authoritative. */
	KNOT_NODE_FLAGS_AUTH =            1 << 0,
	/*! \brief Node is a delegation point (i.e. marking a zone cut). */
	KNOT_NODE_FLAGS_DELEG =           1 << 1,
	/*! \brief Node is not authoritative (i.e. below a zone cut). */
	KNOT_NODE_FLAGS_NONAUTH =         1 << 2,
	/*! \brief Node is an apex node. */
	KNOT_NODE_FLAGS_APEX =            1 << 3,
	/*! \brief NSEC/NSEC3 was removed from this node. */
	KNOT_NODE_FLAGS_REMOVED_NSEC =    1 << 4,
	/*! \brief Node is empty and will be deleted after update. */
	KNOT_NODE_FLAGS_EMPTY =           1 << 5,
	/*! \brief Node has a wildcard child. */
	KNOT_NODE_FLAGS_WILDCARD_CHILD =  1 << 6
} knot_node_flags_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates and initializes new node structure.
 *
 * \return Newly created node or NULL if an error occured.
 */
knot_node_t *knot_node_new(const knot_dname_t *owner);

/*!
 * \brief Adds an RRSet to the node.
 *
 * \param node Node to add the RRSet to.
 * \param rrset RRSet to add.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR if the RRSet could not be inserted.
 */
int knot_node_add_rrset(knot_node_t *node, const knot_rrset_t *rrset, bool *ttl_err);

knot_rdataset_t *knot_node_rdataset(const knot_node_t *node, uint16_t type);

/*!
 * \brief Returns the RRSet of the given type from the node (non-const version).
 *
 * \param node Node to get the RRSet from.
 * \param type Type of the RRSet to retrieve.
 *
 * \return RRSet from node \a node having type \a type, or NULL if no such
 *         RRSet exists in this node.
 */
knot_rrset_t *knot_node_create_rrset(const knot_node_t *node, uint16_t type);

void knot_node_remove_rrset(knot_node_t *node, uint16_t type);

/*!
 * \brief Sets the parent of the node.
 *
 * \param node Node to set the parent of.
 * \param parent Parent to set to the node.
 */
void knot_node_set_parent(knot_node_t *node, knot_node_t *parent);

/*!
 * \brief Destroys the RRSets within the node structure.
 *
 * \param node Node to be destroyed.
 */
void knot_node_free_rrsets(knot_node_t *node);

/*!
 * \brief Destroys the node structure.
 *
 * Does not destroy the RRSets within the node.
 * Also sets the given pointer to NULL.
 *
 * \param node Node to be destroyed.
 * \param free_owner Set to 0 if you do not want the owner domain name to be
 *                   destroyed also. Set to <> 0 otherwise.
 * \param fix_refs
 *
 * \todo Document missing parameters.
 */
void knot_node_free(knot_node_t **node);

int knot_node_shallow_copy(const knot_node_t *from, knot_node_t **to);

/*!
 * \brief Checks whether node contains an RRSIG for given type.
 *
 * \param node  Node to check in.
 * \param node  Type to check for.
 *
 * \return True/False.
 */
bool knot_node_rrtype_is_signed(const knot_node_t *node, uint16_t type);

/*!
 * \brief Checks whether node contains RRSet for given type.
 *
 * \param node  Node to check in.
 * \param node  Type to check for.
 *
 * \return True/False.
 */
bool knot_node_rrtype_exists(const knot_node_t *node, uint16_t type);

/*!
 * \brief Returns RRSet structure initialized with data from node.
 *
 * \param node   Node containing RRSet.
 * \param type   RRSet type we want to get.
 *
 * \return RRSet structure with wanted type, or empty RRSet.
 */
static inline knot_rrset_t knot_node_rrset(const knot_node_t *node, uint16_t type)
{
	knot_rrset_t rrset;
	for (uint16_t i = 0; node && i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			struct rr_data *rr_data = &node->rrs[i];
			rrset.owner = node->owner;
			rrset.type = type;
			rrset.rclass = KNOT_CLASS_IN;
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
static inline knot_rrset_t knot_node_rrset_at(const knot_node_t *node, size_t pos)
{
	knot_rrset_t rrset;
	if (node == NULL || pos >= node->rrset_count) {
		knot_rrset_init_empty(&rrset);
		return rrset;
	}

	struct rr_data *rr_data = &node->rrs[pos];
	rrset.owner = node->owner;
	rrset.type = rr_data->type;
	rrset.rclass = KNOT_CLASS_IN;
	rrset.rrs = rr_data->rrs;
	rrset.additional = rr_data->additional;

	return rrset;
}

#endif /* _KNOT_NODE_H_ */

/*! @} */
