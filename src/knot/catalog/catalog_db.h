/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/journal/knot_lmdb.h"
#include "libknot/libknot.h"

#define CATALOG_VERSION		"1.0"
#define CATALOG_ZONE_VERSION	"2" // must be just one char long
#define CATALOG_ZONES_LABEL	"\x05""zones"
#define CATALOG_GROUP_LABEL	"\x05""group"
#define CATALOG_GROUP_MAXLEN	255

typedef struct catalog {
	knot_lmdb_db_t db;
	knot_lmdb_txn_t *ro_txn; // persistent RO transaction
	knot_lmdb_txn_t *rw_txn; // temporary RW transaction

	// private
	knot_lmdb_txn_t *old_ro_txn;
} catalog_t;

/*!
 * \brief Append a prefix dname to a dname in a storage.
 *
 * \return New dname length.
 */
size_t catalog_dname_append(knot_dname_storage_t storage, const knot_dname_t *name);

/*!
 * \brief Return the number of bytes that subname has more than name.
 *
 * \return -1 if subname is not subname of name
 */
int catalog_bailiwick_shift(const knot_dname_t *subname, const knot_dname_t *name);

/*!
 * \brief Initialize catalog structure.
 *
 * \param cat        Catalog structure.
 * \param path       Path to LMDB for catalog.
 * \param mapsize    Mapsize of the LMDB.
 */
void catalog_init(catalog_t *cat, const char *path, size_t mapsize);

/*!
 * \brief Check if the catalog exists on the filesystem.
 *
 * \param cat        Catalog structure.
 *
 * \retval KNOT_EOK     The catalog exists (and is accessible for stat() ).
 * \retval KNOT_ENODB   The catalog doesn't exist.
 * \return KNOT_E* explaining why stat() failed.
 */
int catalog_exists(catalog_t *cat);

/*!
 * \brief Open the catalog LMDB, create it if not exists.
 *
 * \param cat   Catalog to be opened.
 *
 * \return KNOT_E*
 */
int catalog_open(catalog_t *cat);

/*!
 * \brief Start a temporary RW transaction in the catalog.
 *
 * \param cat   Catalog in question.
 *
 * \return KNOT_E*
 */
int catalog_begin(catalog_t *cat);

/*!
 * \brief End using the temporary RW txn, refresh the persistent RO txn.
 *
 * \param cat   Catalog in question.
 *
 * \return KNOT_E*
 */
int catalog_commit(catalog_t *cat);

/*!
 * \brief Abort temporary RW txn.
 */
void catalog_abort(catalog_t *cat);

/*!
 * \brief Free up old txns.
 *
 * \note This must be called after catalog_commit() with a delay of synchronize_rcu().
 *
 * \param cat   Catalog.
 */
void catalog_commit_cleanup(catalog_t *cat);

/*!
 * \brief Close the catalog and de-init the structure.
 *
 * \param cat   Catalog to be closed.
 */
void catalog_deinit(catalog_t *cat);

/*!
 * \brief Add a member zone to the catalog database.
 *
 * \param cat       Catalog to be augmented.
 * \param member    Member zone name.
 * \param owner     Owner of the PTR record in catalog zone, respective to the member zone.
 * \param catzone   Name of the catalog zone whose it's the member.
 * \param group     Configuration group of the member.
 *
 * \return KNOT_E*
 */
int catalog_add(catalog_t *cat, const knot_dname_t *member,
                const knot_dname_t *owner, const knot_dname_t *catzone,
                const char *group);

/*!
 * \brief Delete a member zone from the catalog database.
 *
 * \param cat       Catalog to be removed from.
 * \param member    Member zone to be removed.
 *
 * \return KNOT_E*
 */
int catalog_del(catalog_t *cat, const knot_dname_t *member);

/*!
 * \brief Find catz name of the catalog owning this member.
 *
 * \note This function may be called in multithreaded operation.
 *
 * \param cat       Catalog database.
 * \param member    Member to search for.
 * \param catz      Out: name of catalog zone it resides in.
 * \param group     Out: configuration group the member resides in.
 * \param tofree    Out: a pointer that has to be freed later.
 *
 * \return KNOT_E*
 */
int catalog_get_catz(catalog_t *cat, const knot_dname_t *member,
                     const knot_dname_t **catz, const char **group, void **tofree);

/*!
 * \brief Check if this member exists in any catalog zone.
 */
bool catalog_has_member(catalog_t *cat, const knot_dname_t *member);

/*!
 * \brief Check if exactly this record (member, owner, catz) is in catalog DB.
 */
bool catalog_contains_exact(catalog_t *cat, const knot_dname_t *member,
                            const knot_dname_t *owner, const knot_dname_t *catz);

typedef int (*catalog_apply_cb_t)(const knot_dname_t *member, const knot_dname_t *owner,
                                  const knot_dname_t *catz, const char *group, void *ctx);
/*!
 * \brief Iterate through catalog database, applying callback.
 *
 * \param cat          Catalog to be iterated.
 * \param for_member   (Optional) Iterate only on records for this member name.
 * \param cb           Callback to be called.
 * \param ctx          Context for this callback.
 * \param rw           Use read-write transaction.
 *
 * \return KNOT_E*
 */
int catalog_apply(catalog_t *cat, const knot_dname_t *for_member,
                  catalog_apply_cb_t cb, void *ctx, bool rw);

/*!
 * \brief Copy records from one catalog database to other.
 *
 * \param from           Catalog DB to copy from.
 * \param to             Catalog DB to copy to.
 * \param cat_only       Optional: copy only records for this catalog zone.
 * \param read_rw_txn    Use RW txn for read operations.
 *
 * \return KNOT_E*
 */
int catalog_copy(knot_lmdb_db_t *from, knot_lmdb_db_t *to,
                 const knot_dname_t *cat_only, bool read_rw_txn);
