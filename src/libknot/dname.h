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
/*!
 * \file
 *
 * \brief Domain name structure and API for manipulating it.
 *
 * \addtogroup dname
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "libknot/attribute.h"
#include "libknot/consts.h"
#include "libknot/error.h"
#include "libknot/mm_ctx.h"
#include "libknot/packet/wire.h"

/*! \brief Type representing a domain name in wire format. */
typedef uint8_t knot_dname_t;

/*! \brief Local domain name storage. */
typedef uint8_t knot_dname_storage_t[KNOT_DNAME_MAXLEN];

/*!
 * \brief Check dname on the wire for constraints.
 *
 * If the name passes such checks, it is safe to be used in rest of the functions.
 *
 * \param name  Name on the wire.
 * \param endp  Name boundary.
 * \param pkt   Wire.
 *
 * \retval (compressed) size of the domain name.
 * \retval KNOT_EINVAL
 * \retval KNOT_EMALF
 */
_pure_ _mustcheck_
int knot_dname_wire_check(const uint8_t *name, const uint8_t *endp,
                          const uint8_t *pkt);

/*!
 * \brief Duplicates the given domain name to a local storage.
 *
 * \param dst   Destination storage.
 * \param name  Domain name to be copied.
 *
 * \retval size of the domain name.
 * \retval 0 if invalid argument.
 */
_mustcheck_
size_t knot_dname_store(knot_dname_storage_t dst, const knot_dname_t *name);

/*!
 * \brief Duplicates the given domain name.
 *
 * \param name  Domain name to be copied.
 * \param mm    Memory context.
 *
 * \return New domain name which is an exact copy of \a name.
 */
_mustcheck_
knot_dname_t *knot_dname_copy(const knot_dname_t *name, knot_mm_t *mm);

/*!
 * \brief Copy name to wire as is, no compression pointer expansion will be done.
 *
 * \param dst     Destination wire.
 * \param src     Source name.
 * \param maxlen  Maximum wire length.
 *
 * \return the number of bytes written or negative error code
 */
int knot_dname_to_wire(uint8_t *dst, const knot_dname_t *src, size_t maxlen);

/*!
 * \brief Write unpacked name (i.e. compression pointers expanded)
 *
 * \note The function is very similar to the knot_dname_to_wire(), except
 *       it expands compression pointers. E.g. you want to use knot_dname_unpack()
 *       if you copy a dname from incoming packet to some persistent storage.
 *       And you want to use knot_dname_to_wire() if you know the name is not
 *       compressed or you want to copy it 1:1.
 *
 * \param dst     Destination wire.
 * \param src     Source name.
 * \param maxlen  Maximum destination wire size.
 * \param pkt     Name packet wire (for compression pointers).
 *
 * \return number of bytes written
 */
int knot_dname_unpack(uint8_t *dst, const knot_dname_t *src,
                      size_t maxlen, const uint8_t *pkt);

/*!
 * \brief Converts the given domain name to its string representation.
 *
 * \note Output buffer is allocated automatically if dst is NULL.
 *
 * \param dst     Output buffer.
 * \param name    Domain name to be converted.
 * \param maxlen  Output buffer length.
 *
 * \return 0-terminated string if successful, NULL if error.
 */
char *knot_dname_to_str(char *dst, const knot_dname_t *name, size_t maxlen);

/*!
 * \brief This function is a shortcut for \ref knot_dname_to_str with
 *        no output buffer parameters.
 */
_mustcheck_
static inline char *knot_dname_to_str_alloc(const knot_dname_t *name)
{
	return knot_dname_to_str(NULL, name, 0);
}

/*!
 * \brief Creates a dname structure from domain name given in presentation
 *        format.
 *
 * \note The resulting FQDN is stored in the wire format.
 * \note Output buffer is allocated automatically if dst is NULL.
 *
 * \param dst    Output buffer.
 * \param name   Domain name in presentation format (labels separated by dots,
 *               '\0' terminated).
 * \param maxlen Output buffer length.
 *
 * \return New dname if successful, NULL if error.
 */
knot_dname_t *knot_dname_from_str(uint8_t *dst, const char *name, size_t maxlen);

/*!
 * \brief This function is a shortcut for \ref knot_dname_from_str with
 *        no output buffer parameters.
 */
_mustcheck_
static inline knot_dname_t *knot_dname_from_str_alloc(const char *name)
{
	return knot_dname_from_str(NULL, name, 0);
}

/*!
 * \brief Convert name to lowercase.
 *
 * \param name  Domain name to be converted.
 */
void knot_dname_to_lower(knot_dname_t *name);

/*!
 * \brief Returns size of the given domain name.
 *
 * \note If the domain name is compressed, the length of not compressed part
 *       is returned.
 *
 * \param name  Domain name to get the size of.
 *
 * \retval size of the domain name.
 * \retval 0 if invalid argument.
 */
_pure_
size_t knot_dname_size(const knot_dname_t *name);

/*!
 * \brief Returns full size of the given domain name (expanded compression ptrs).
 *
 * \param name  Domain name to get the size of.
 * \param pkt   Related packet (or NULL if unpacked)
 *
 * \retval size of the domain name.
 * \retval 0 if invalid argument.
 */
_pure_
size_t knot_dname_realsize(const knot_dname_t *name, const uint8_t *pkt);

/*!
 * \brief Checks if the domain name is a wildcard.
 *
 * \param name  Domain name to check.
 *
 * \retval true if \a dname is a wildcard domain name.
 * \retval false otherwise.
 */
static inline
bool knot_dname_is_wildcard(const knot_dname_t *name)
{
	return name != NULL && name[0] == 1 && name[1] == '*';
}

/*!
 * \brief Returns the number of labels common for the two domain names (counted
 *        from the rightmost label.
 *
 * \param d1  First domain name.
 * \param d2  Second domain name.
 *
 * \return Number of labels common for the two domain names.
 */
_pure_
size_t knot_dname_matched_labels(const knot_dname_t *d1, const knot_dname_t *d2);

/*!
 * \brief Replaces the suffix of given size in one domain name with other domain
 *        name.
 *
 * \param name    Domain name where to replace the suffix.
 * \param labels  Size of the suffix to be replaced.
 * \param suffix  New suffix to be used as a replacement.
 * \param mm      Memory context.
 *
 * \return New domain name created by replacing suffix of \a dname of size
 *         \a size with \a suffix.
 */
_mustcheck_
knot_dname_t *knot_dname_replace_suffix(const knot_dname_t *name, unsigned labels,
                                        const knot_dname_t *suffix, knot_mm_t *mm);

/*!
 * \brief Destroys the given domain name.
 *
 * \param name  Domain name to be destroyed.
 * \param mm    Memory context.
 */
void knot_dname_free(knot_dname_t *name, knot_mm_t *mm);

/*!
 * \brief Compares two domain names by labels (case sensitive).
 *
 * \param d1  First domain name.
 * \param d2  Second domain name.
 *
 * \retval < 0 if \a d1 goes before \a d2 in canonical order.
 * \retval > 0 if \a d1 goes after \a d2 in canonical order.
 * \retval 0 if the domain names are identical.
 */
_pure_
int knot_dname_cmp(const knot_dname_t *d1, const knot_dname_t *d2);

/*!
 * \brief Compares two domain names (case sensitive).
 *
 * \param d1  First domain name.
 * \param d2  Second domain name.
 *
 * \retval true if the domain names are identical
 * \retval false if the domain names are NOT identical
 */
_pure_
bool knot_dname_is_equal(const knot_dname_t *d1, const knot_dname_t *d2);

/*!
 * \brief Count length of the N first labels.
 *
 * \param name     Domain name.
 * \param nlabels  First N labels.
 * \param pkt      Related packet (or NULL if not compressed).
 *
 * \return Length of the prefix.
 */
_pure_
size_t knot_dname_prefixlen(const uint8_t *name, unsigned nlabels, const uint8_t *pkt);

/*!
 * \brief Return number of labels in the domain name.
 *
 * Terminal nullbyte is not counted.
 *
 * \param name  Domain name.
 * \param pkt   Related packet (or NULL if not compressed).
 *
 * \return Number of labels.
 */
_pure_
size_t knot_dname_labels(const uint8_t *name, const uint8_t *pkt);

/*!
 * \brief Convert domain name from wire to the lookup format.
 *
 * Formats names from rightmost label to the leftmost, separated by the lowest
 * possible character (\\x00). Sorting such formatted names also gives
 * correct canonical order (for NSEC/NSEC3). The first byte of the output
 * contains length of the output.
 *
 * Examples:
 * Name:   lake.example.com.
 * Wire:   \\x04lake\\x07example\\x03com\\x00
 * Lookup: \\x11com\\x00example\\x00lake\\x00
 *
 * Name:   .
 * Wire:   \\x00
 * Lookup: \\x00
 *
 * \param src      Source domain name.
 * \param storage  Memory to store converted name into. Don't use directly!
 *
 * \retval Lookup format if successful (pointer into the storage).
 * \retval NULL on invalid parameters.
 */
uint8_t *knot_dname_lf(const knot_dname_t *src, knot_dname_storage_t storage);

/*!
 * \brief Check whether a domain name is under another one and how deep.
 *
 * \param domain    The longer name to check.
 * \param bailiwick The shorter name to check.
 *
 * \retval >=0 a subdomain nested this many labels.
 * \retval <0 not a subdomain (KNOT_EOUTOFZONE) or another error (KNOT_EINVAL).
 */
static inline
int knot_dname_in_bailiwick(const knot_dname_t *domain, const knot_dname_t *bail)
{
	if (domain == NULL || bail == NULL) {
		return KNOT_EINVAL;
	}
	int label_diff = knot_dname_labels(domain, NULL) - knot_dname_labels(bail, NULL);
	if (label_diff < 0) return KNOT_EOUTOFZONE;
	for (int i = 0; i < label_diff; ++i) {
		domain = knot_wire_next_label(domain, NULL);
	}
	return knot_dname_is_equal(domain, bail) ? label_diff : KNOT_EOUTOFZONE;
}

/*!
 * \brief Checks if one domain name is a (strict) subdomain of other.
 *
 * \param sub     Domain name to be the possible subdomain.
 * \param domain  Domain name to be the possible parent domain.
 *
 * \retval true \a sub is a (strict) subdomain of \a domain.
 * \retval false otherwise.
 */
static inline
bool knot_dname_is_sub(const knot_dname_t *sub, const knot_dname_t *domain)
{
	return knot_dname_in_bailiwick(sub, domain) > 0;
}

/*!
 * \brief Check if the domain name is a subdomain of or equal to other.
 *
 * \param domain  Domain name to be the possible parent domain.
 * \param sub     Domain name to be the possible subdomain.
 *
 * \retval true \a sub us a subdomain or equal to \a domain.
 * \retval false otherwise.
 */
static inline
bool knot_dname_in(const knot_dname_t *domain, const knot_dname_t *sub)
{
	return knot_dname_in_bailiwick(sub, domain) >= 0;
}


/*! @} */
