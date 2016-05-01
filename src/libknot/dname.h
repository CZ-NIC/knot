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
/*!
 * \file
 *
 * \brief Domain name structure and API for manipulating it.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "libknot/attribute.h"
#include "libknot/mm_ctx.h"

/*! \brief Type representing a domain name in wire format. */
typedef uint8_t knot_dname_t;

/*!
 * \brief Check dname on the wire for constraints.
 *
 * If the name passes such checks, it is safe to be used in rest of the functions.
 *
 * \param name Name on the wire.
 * \param endp Name boundary.
 * \param pkt Wire.
 *
 * \retval (compressed) size of the domain name.
 * \retval KNOT_EMALF
 * \retval KNOT_ESPACE
 */
_pure_ _mustcheck_
int knot_dname_wire_check(const uint8_t *name, const uint8_t *endp,
                          const uint8_t *pkt);

/*!
 * \brief Parse dname from wire.
 *
 * \param pkt Message in wire format.
 * \param pos Position of the domain name on wire.
 * \param maxpos Domain name length.
 * \param mm Memory context.
 *
 * \return parsed domain name or NULL.
 */
_mustcheck_
knot_dname_t *knot_dname_parse(const uint8_t *pkt, size_t *pos, size_t maxpos,
                               knot_mm_t *mm);

/*!
 * \brief Duplicates the given domain name.
 *
 * \param name Domain name to be copied.
 *
 * \return New domain name which is an exact copy of \a dname.
 */
_mustcheck_
knot_dname_t *knot_dname_copy(const knot_dname_t *name, knot_mm_t *mm);

/*!
 * \brief Duplicates part of the given domain name.
 *
 * \param name Domain name to be copied.
 * \param len Part length.
 *
 * \return New domain name which is an partial copy of \a dname.
 */
_mustcheck_
knot_dname_t *knot_dname_copy_part(const knot_dname_t *name, unsigned len,
                                   knot_mm_t *mm);

/*!
 * \brief Copy name to wire as is, no compression pointer expansion will be done.
 *
 * \param dst Destination wire.
 * \param src Source name.
 * \param maxlen Maximum wire length.
 *
 * \return number of bytes written
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
 * \param dst Destination wire.
 * \param src Source name.
 * \param maxlen Maximum destination wire size.
 * \param pkt Name packet wire (for compression pointers).
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
 * \param dst    Output buffer.
 * \param name   Domain name to be converted.
 * \param maxlen Output buffer length.
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
 * \note Name must not be compressed.
 *
 * \param name Domain name to be converted.
 *
 * \return KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_dname_to_lower(knot_dname_t *name);

/*!
 * \brief Returns size of the given domain name.
 *
 * \note If the domain name is compressed, the length of not compressed part
 *       is returned.
 *
 * \param name Domain name to get the size of.
 *
 * \retval size of the domain name.
 * \retval KNOT_EINVAL
 */
_pure_
int knot_dname_size(const knot_dname_t *name);

/*!
 * \brief Returns wire size of the given domain name (expanded compression ptrs).
 *
 * \param name Domain name to get the size of.
 * \param pkt Related packet (or NULL if unpacked)
 *
 * \retval size of the domain name.
 * \retval KNOT_EINVAL
 */
_pure_
int knot_dname_realsize(const knot_dname_t *name, const uint8_t *pkt);

/*!
 * \brief Checks if one domain name is a subdomain of other.
 *
 * \param sub Domain name to be the possible subdomain.
 * \param domain Domain name to be the possible parent domain.
 *
 * \retval true \a sub is a subdomain of \a domain.
 * \retval false otherwise.
 */
_pure_
bool knot_dname_is_sub(const knot_dname_t *sub, const knot_dname_t *domain);

/*!
 * \brief Check if the domain name is a subdomain of or equal to other.
 *
 * \param domain Domain name to be the possible parent domain.
 * \param sub Domain name to be the possible subdomain.
 *
 * \retval true \a sub us a subdomain or equal to \a domain.
 * \retval false otherwise.
 */
_pure_
bool knot_dname_in(const knot_dname_t *domain, const knot_dname_t *sub);

/*!
 * \brief Checks if the domain name is a wildcard.
 *
 * \param name Domain name to check.
 *
 * \retval true if \a dname is a wildcard domain name.
 * \retval false otherwise.
 */
_pure_
bool knot_dname_is_wildcard(const knot_dname_t *name);

/*!
 * \brief Returns the number of labels common for the two domain names (counted
 *        from the rightmost label.
 *
 * \param d1 First domain name.
 * \param d2 Second domain name.
 *
 * \return Number of labels common for the two domain names.
 */
_pure_
int knot_dname_matched_labels(const knot_dname_t *d1, const knot_dname_t *d2);

/*!
 * \brief Replaces the suffix of given size in one domain name with other domain
 *        name.
 *
 * \param name Domain name where to replace the suffix.
 * \param labels Size of the suffix to be replaced.
 * \param suffix New suffix to be used as a replacement.
 *
 * \return New domain name created by replacing suffix of \a dname of size
 *         \a size with \a suffix.
 */
_mustcheck_
knot_dname_t *knot_dname_replace_suffix(const knot_dname_t *name, unsigned labels,
                                        const knot_dname_t *suffix);

/*!
 * \brief Destroys the given domain name.
 *
 * Frees also the data within the struct. This is somewhat different behaviour
 * than that of RDATA and RRSet structures which do not deallocate their
 * contents.
 *
 * Sets the given pointer to NULL.
 *
 * \param name Domain name to be destroyed.
 */
void knot_dname_free(knot_dname_t **name, knot_mm_t *mm);

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
_pure_
int knot_dname_cmp(const knot_dname_t *d1, const knot_dname_t *d2);

/*!
 * \brief Compare domain name by labels.
 *
 * \todo No case insensitivity, flags...
 *
 * \warning Since it would be hard to catch errors, because negative value
 *          is also a good result, there are assertions that expect neither
 *          d1 or d2 to be NULL.
 *
 * \param d1 Domain name.
 * \param d2 Domain name.
 * \param pkt Packet wire related to names (or NULL).
 *
 * \retval 0 if they are identical
 * \retval 1 if d1 > d2
 * \retval -1 if d1 < d2
 */
_pure_
int knot_dname_cmp_wire(const knot_dname_t *d1, const knot_dname_t *d2,
                        const uint8_t *pkt);

/*!
 * \brief Compares two domain names (case sensitive).
 *
 * \param d1 First domain name.
 * \param d2 Second domain name.
 *
 * \retval true if the domain names are identical
 * \retval false if the domain names are NOT identical
 */
_pure_
bool knot_dname_is_equal(const knot_dname_t *d1, const knot_dname_t *d2);

/*!
 * \brief Concatenates two domain names.
 *
 * \param d1 First domain name (will be modified).
 * \param d2 Second domain name (will not be modified).
 *
 * \return The concatenated domain name or NULL
 */
knot_dname_t *knot_dname_cat(knot_dname_t *d1, const knot_dname_t *d2);

/*!
 * \brief Cound length of the N first labels.
 *
 * \param name Domain name.
 * \param nlabels N first labels.
 * \param pkt Related packet (or NULL if not compressed).
 *
 * \retval length of the prefix
 */
_pure_
int knot_dname_prefixlen(const uint8_t *name, unsigned nlabels, const uint8_t *pkt);

/*!
 * \brief Return number of labels in the domain name.
 *
 * Terminal nullbyte is not counted.
 *
 * \param name Domain name.
 * \param pkt Related packet (or NULL if not compressed).
 */
_pure_
int knot_dname_labels(const uint8_t *name, const uint8_t *pkt);

/*!
 * \brief Align name end-to-end and return number of common suffix labels.
 *
 * \param d1 Domain name.
 * \param d1_labels Number of labels in d1.
 * \param d2 Domain name.
 * \param d2_labels Number of labels in d2.
 * \param wire Packet wire related to names (or NULL).
 */
int knot_dname_align(const uint8_t **d1, uint8_t d1_labels,
                     const uint8_t **d2, uint8_t d2_labels,
                     uint8_t *wire);

/*!
 * \brief Convert domain name from wire to lookup format.
 *
 * Formats names from rightmost label to the leftmost, separated by the lowest
 * possible character (\x00). Sorting such formatted names also gives
 * correct canonical order (for NSEC/NSEC3).
 *
 * Example:
 * Name: lake.example.com. Wire: \x04lake\x07example\x03com\x00
 * Lookup format com\x00example\x00lake\x00
 *
 * Maximum length of such a domain name is KNOT_DNAME_MAXLEN characters.
 *
 * \param dst Memory to store converted name into.
 * \param src Source domain name.
 * \param pkt Source name packet (NULL if not any).
 *
 * \retval KNOT_EOK if successful
 * \retval KNOT_EINVAL on invalid parameters
 */
int knot_dname_lf(uint8_t *dst, const knot_dname_t *src, const uint8_t *pkt);

/*! @} */
