/*!
 * \file dname.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Domain name structure and API for manipulating it.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_DNAME_H_
#define _KNOT_DNSLIB_DNAME_H_

#include <stdint.h>

struct dnslib_node;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for representing a domain name.
 *
 * Stores the domain name in wire format.
 *
 * \todo Consider restricting to FQDN only (see dnslib_dname_new_from_str()).
 */
struct dnslib_dname {
	uint8_t *name;	/*!< Wire format of the domain name. */
	/*!
	 * \brief Size of the domain name in octets.
	 * \todo Is this needed? Every dname should end with \0 or pointer.
	 */
	unsigned int size;
	uint8_t *labels;
	short label_count;
	struct dnslib_node *node; /*!< Zone node the domain name belongs to. */
};

typedef struct dnslib_dname dnslib_dname_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Creates empty dname structure (no name, no owner node).
 *
 * \return Newly allocated and initialized dname structure.
 *
 * \todo Possibly useless.
 */
dnslib_dname_t *dnslib_dname_new();

/*!
 * \brief Creates a dname structure from domain name given in presentation
 *        format.
 *
 * The resulting domain name is stored in wire format, but it may not end with
 * root label (0).
 *
 * \param name Domain name in presentation format (labels separated by dots).
 * \param size Size of the domain name (count of characters with all dots).
 * \param node Zone node the domain name belongs to. Set to NULL if not
 *             applicable.
 *
 * \return Newly allocated and initialized dname structure representing the
 *         given domain name.
 */
dnslib_dname_t *dnslib_dname_new_from_str(const char *name, unsigned int size,
                                          struct dnslib_node *node);

/*!
 * \brief Creates a dname structure from domain name given in wire format.
 *
 * \note The name is copied into the structure.
 * \note If the given name is not a FQDN, the result will be neither.
 *
 * \param name Domain name in wire format.
 * \param size Size of the domain name in octets.
 * \param node Zone node the domain name belongs to. Set to NULL if not
 *             applicable.
 *
 * \return Newly allocated and initialized dname structure representing the
 *         given domain name.
 *
 * \todo This function does not check if the given data is in correct wire
 *       format at all. It thus creates a invalid domain name, which if passed
 *       e.g. to dnslib_dname_to_str() may result in crash. Decide whether it
 *       is OK to retain this and check the data in other functions before
 *       calling this one, or if it should verify the given data.
 */
dnslib_dname_t *dnslib_dname_new_from_wire(const uint8_t *name,
                                           unsigned int size,
                                           struct dnslib_node *node);

dnslib_dname_t *dnslib_dname_parse_from_wire(const uint8_t *name,
                                             unsigned int max_size,
                                             struct dnslib_node *node);

/*!
 * \brief Initializes domain name by the name given in wire format.
 *
 * \note The name is copied into the structure.
 * \note If there is any name in the structure, it will be replaced.
 * \note If the given name is not a FQDN, the result will be neither.
 *
 * \param name Domain name in wire format.
 * \param size Size of the domain name in octets.
 * \param node Zone node the domain name belongs to. Set to NULL if not
 *             applicable.
 * \param target Domain name structure to initialize.
 *
 * \retval DNSLIB_EOK on success.
 * \retval DNSLIB_ENOMEM if allocation of labels info failed.
 * \retval DNSLIB_EBADARG if name or target is null.
 *
 * \todo This function does not check if the given data is in correct wire
 *       format at all. It thus creates a invalid domain name, which if passed
 *       e.g. to dnslib_dname_to_str() may result in crash. Decide whether it
 *       is OK to retain this and check the data in other functions before
 *       calling this one, or if it should verify the given data.
 */
int dnslib_dname_from_wire(const uint8_t *name, unsigned int size,
                           struct dnslib_node *node, dnslib_dname_t *target);

/*!
 * \brief Copies the given domain name.
 *
 * \param dname Domain name to be copied.
 *
 * \return New domain name which is an exact copy of \a dname.
 */
dnslib_dname_t *dnslib_dname_copy(const dnslib_dname_t *dname);

/*!
 * \brief Converts the given domain name to string representation.
 *
 * \note Allocates new memory, remember to free it.
 *
 * \param dname Domain name to be converted.
 *
 * \return 0-terminated string representing the given domain name in
 *         presentation format.
 */
char *dnslib_dname_to_str(const dnslib_dname_t *dname);

/*!
 * \brief Returns the domain name in wire format.
 *
 * \param dname Domain name.
 *
 * \return Wire format of the domain name.
 */
const uint8_t *dnslib_dname_name(const dnslib_dname_t *dname);

/*!
 * \brief Returns size of the given domain name.
 *
 * \param dname Domain name to get the size of.
 *
 * \return Size of the domain name in wire format in octets.
 */
unsigned int dnslib_dname_size(const dnslib_dname_t *dname);

/*!
 * \brief Returns size of a part of domain name.
 *
 * \param dname Domain name.
 * \param labels Count of labels to get the size of (counted from left).
 *
 * \return Size of first \a labels labels of \a dname, counted from left.
 */
uint8_t dnslib_dname_size_part(const dnslib_dname_t *dname, int labels);

/*!
 * \brief Returns the zone node the domain name belongs to.
 *
 * \param dname Domain name to get the zone node of.
 *
 * \return Zone node the domain name belongs to or NULL if none.
 */
const struct dnslib_node *dnslib_dname_node(const dnslib_dname_t *dname);

/*!
 * \brief Checks if the given domain name is a fully-qualified domain name.
 *
 * \param dname Domain name to check.
 *
 * \retval <> 0 if \a dname is a FQDN.
 * \retval 0 otherwise.
 */
int dnslib_dname_is_fqdn(const dnslib_dname_t *dname);

/*!
 * \brief Creates new domain name by removing leftmost label from \a dname.
 *
 * \param dname Domain name to remove the first label from.
 *
 * \return New domain name with the same labels as \a dname, except for the
 *         leftmost label, which is removed.
 */
dnslib_dname_t *dnslib_dname_left_chop(const dnslib_dname_t *dname);

/*!
 * \brief Removes leftmost label from \a dname.
 *
 * \param dname Domain name to remove the first label from.
 */
void dnslib_dname_left_chop_no_copy(dnslib_dname_t *dname);

/*!
 * \brief Checks if one domain name is a subdomain of other.
 *
 * \param sub Domain name to be the possible subdomain.
 * \param domain Domain name to be the possible parent domain.
 *
 * \retval <> 0 if \a sub is a subdomain of \a domain.
 * \retval 0 otherwise.
 */
int dnslib_dname_is_subdomain(const dnslib_dname_t *sub,
                              const dnslib_dname_t *domain);

/*!
 * \brief Checks if the domain name is a wildcard.
 *
 * \param dname Domain name to check.
 *
 * \retval <> 0 if \a dname is a wildcard domain name.
 * \retval 0 otherwise.
 */
int dnslib_dname_is_wildcard(const dnslib_dname_t *dname);

/*!
 * \brief Returns the number of labels common for the two domain names (counted
 *        from the rightmost label.
 *
 * \param dname1 First domain name.
 * \param dname2 Second domain name.
 *
 * \return Number of labels common for the two domain names.
 */
int dnslib_dname_matched_labels(const dnslib_dname_t *dname1,
                                const dnslib_dname_t *dname2);

/*!
 * \brief Returns the number of labels in the domain name.
 *
 * \param dname Domain name to get the label count of.
 *
 * \return Number of labels in \a dname.
 *
 * \todo Find out if this counts the root label also.
 */
int dnslib_dname_label_count(const dnslib_dname_t *dname);

/*!
 * \brief Returns the size of the requested label in the domain name.
 *
 * \param dname Domain name to get the label size from.
 * \param i Index of the label (0 is the leftmost label).
 *
 * \return Size of \a i-th label in \a dname (counted from left).
 */
uint8_t dnslib_dname_label_size(const dnslib_dname_t *dname, int i);

/*!
 * \brief Replaces the suffix of given size in one domain name with other domain
 *        name.
 *
 * \param dname Domain name where to replace the suffix.
 * \param size Size of the suffix to be replaced.
 * \param suffix New suffix to be used as a replacement.
 *
 * \return New domain name created by replacing suffix of \a dname of size
 *         \a size with \a suffix.
 */
dnslib_dname_t *dnslib_dname_replace_suffix(const dnslib_dname_t *dname,
                                            int size,
                                            const dnslib_dname_t *suffix);

/*!
 * \brief Destroys the given domain name.
 *
 * Frees also the data within the struct. This is somewhat different behaviour
 * than that of RDATA and RRSet structures which do not deallocate their
 * contents.
 *
 * Sets the given pointer to NULL.
 *
 * \param dname Domain name to be destroyed.
 */
void dnslib_dname_free(dnslib_dname_t **dname);

/*!
 * \brief Compares two domain names (case insensitive).
 *
 * \param d1 First domain name.
 * \param d2 Second domain name.
 *
 * \retval < 0 if \a d1 goes before \a d2 in canonical order.
 * \retval > 0 if \a d1 goes after \a d2 in canonical order.
 * \retval 0 if the domain names are identical.
 */
int dnslib_dname_compare(const dnslib_dname_t *d1, const dnslib_dname_t *d2);

/*!
 * \brief Compares two domain names (case sensitive).
 *
 * \param d1 First domain name.
 * \param d2 Second domain name.
 *
 * \retval < 0 if \a d1 goes before \a d2 in canonical order.
 * \retval > 0 if \a d1 goes after \a d2 in canonical order.
 * \retval 0 if the domain names are identical.
 */
int dnslib_dname_compare_cs(const dnslib_dname_t *d1, const dnslib_dname_t *d2);

/*!
 * \brief Concatenates two domain names.
 *
 * \note Member \a node is ignored, i.e. preserved.
 *
 * \param d1 First domain name (will be modified).
 * \param d2 Second domain name (will not be modified).
 *
 * \return The concatenated domain name (i.e. modified \a d1) or NULL if
 *         the operation is not valid (e.g. \a d1 is a FQDN).
 */
dnslib_dname_t *dnslib_dname_cat(dnslib_dname_t *d1, const dnslib_dname_t *d2);

#endif /* _KNOT_DNSLIB_DNAME_H_ */

/*! @} */
