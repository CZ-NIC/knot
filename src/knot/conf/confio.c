/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/log.h"
#include "knot/conf/confdb.h"
#include "knot/conf/confio.h"
#include "knot/conf/module.h"
#include "knot/conf/tools.h"

#define FCN(io)	(io->fcn != NULL) ? io->fcn(io) : KNOT_EOK;

static void io_reset_val(
	conf_io_t *io,
	const yp_item_t *key0,
	const yp_item_t *key1,
	const uint8_t *id,
	size_t id_len,
	bool id_as_data,
	conf_val_t *val)
{
	io->key0 = key0;
	io->key1 = key1;
	io->id = id;
	io->id_len = id_len;
	io->id_as_data = id_as_data;
	io->data.val = val;
	io->data.bin = NULL;
}

static void io_reset_bin(
	conf_io_t *io,
	const yp_item_t *key0,
	const yp_item_t *key1,
	const uint8_t *id,
	size_t id_len,
	const uint8_t *bin,
	size_t bin_len)
{
	io_reset_val(io, key0, key1, id, id_len, false, NULL);
	io->data.bin = bin;
	io->data.bin_len = bin_len;
}

int conf_io_begin(
	bool child)
{
	assert(conf() != NULL);

	if (conf()->io.txn != NULL && !child) {
		return KNOT_TXN_EEXISTS;
	} else if (conf()->io.txn == NULL && child) {
		return KNOT_TXN_ENOTEXISTS;
	}

	knot_db_txn_t *parent = conf()->io.txn;
	knot_db_txn_t *txn = (parent == NULL) ? conf()->io.txn_stack : parent + 1;
	if (txn >= conf()->io.txn_stack + CONF_MAX_TXN_DEPTH) {
		return KNOT_TXN_EEXISTS;
	}

	// Start the writing transaction.
	int ret = knot_db_lmdb_txn_begin(conf()->db, txn, parent, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	conf()->io.txn = txn;

	// Reset master transaction flags.
	if (!child) {
		conf()->io.flags = CONF_IO_FACTIVE;
		if (conf()->io.zones != NULL) {
			trie_clear(conf()->io.zones);
		}
	}

	return KNOT_EOK;
}

int conf_io_commit(
	bool child)
{
	assert(conf() != NULL);

	if (conf()->io.txn == NULL ||
	    (child && conf()->io.txn == conf()->io.txn_stack)) {
		return KNOT_TXN_ENOTEXISTS;
	}

	knot_db_txn_t *txn = child ? conf()->io.txn : conf()->io.txn_stack;

	// Commit the writing transaction.
	int ret = conf()->api->txn_commit(txn);

	conf()->io.txn = child ? txn - 1 : NULL;

	return ret;
}

void conf_io_abort(
	bool child)
{
	assert(conf() != NULL);

	if (conf()->io.txn == NULL ||
	    (child && conf()->io.txn == conf()->io.txn_stack)) {
		return;
	}

	knot_db_txn_t *txn = child ? conf()->io.txn : conf()->io.txn_stack;

	// Abort the writing transaction.
	conf()->api->txn_abort(txn);
	conf()->io.txn = child ? txn - 1 : NULL;

	// Reset master transaction flags.
	if (!child) {
		conf()->io.flags = YP_FNONE;
		if (conf()->io.zones != NULL) {
			trie_clear(conf()->io.zones);
		}
	}
}

static int list_section(
	const yp_item_t *items,
	const yp_item_t **item,
	conf_io_t *io)
{
	for (*item = items; (*item)->name != NULL; (*item)++) {
		int ret = FCN(io);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int conf_io_list(
	const char *key0,
	conf_io_t *io)
{
	if (io == NULL) {
		return KNOT_EINVAL;
	}

	assert(conf() != NULL);

	// List schema sections by default.
	if (key0 == NULL) {
		io_reset_val(io, NULL, NULL, NULL, 0, false, NULL);

		return list_section(conf()->scheme, &io->key0, io);
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(&conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check the input.
	int ret = yp_scheme_check_str(ctx, key0, NULL, NULL, NULL);
	if (ret != KNOT_EOK) {
		goto list_error;
	}

	yp_node_t *node = &ctx->nodes[ctx->current];

	// Check for non-group item.
	if (node->item->type != YP_TGRP) {
		ret = KNOT_ENOTSUP;
		goto list_error;
	}

	io_reset_val(io, node->item, NULL, NULL, 0, false, NULL);

	ret = list_section(node->item->sub_items, &io->key1, io);
list_error:
	yp_scheme_check_deinit(ctx);

	return ret;
}

static int diff_item(
	conf_io_t *io)
{
	// Process an identifier item.
	if ((io->key0->flags & YP_FMULTI) != 0 && io->key0->var.g.id == io->key1) {
		bool old_id, new_id;

		// Check if a removed identifier.
		int ret = conf_db_get(conf(), &conf()->read_txn, io->key0->name,
		                      NULL, io->id, io->id_len, NULL);
		switch (ret) {
		case KNOT_EOK:
			old_id = true;
			break;
		case KNOT_ENOENT:
		case KNOT_YP_EINVAL_ID:
			old_id = false;
			break;
		default:
			return ret;
		}

		// Check if an added identifier.
		ret = conf_db_get(conf(), conf()->io.txn, io->key0->name, NULL,
		                  io->id, io->id_len, NULL);
		switch (ret) {
		case KNOT_EOK:
			new_id = true;
			break;
		case KNOT_ENOENT:
		case KNOT_YP_EINVAL_ID:
			new_id = false;
			break;
		default:
			return ret;
		}

		// Check if valid identifier.
		if (!old_id && !new_id) {
			return KNOT_YP_EINVAL_ID;
		}

		if (old_id != new_id) {
			io->id_as_data = true;
			io->type = old_id ? OLD : NEW;

			// Process the callback.
			ret = FCN(io);

			// Reset the modified parameters.
			io->id_as_data = false;
			io->type = NONE;

			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		return KNOT_EOK;
	}

	conf_val_t old_val, new_val;

	// Get the old item value.
	conf_db_get(conf(), &conf()->read_txn, io->key0->name, io->key1->name,
	            io->id, io->id_len, &old_val);
	switch (old_val.code) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		break;
	default:
		return old_val.code;
	}

	// Get the new item value.
	conf_db_get(conf(), conf()->io.txn, io->key0->name, io->key1->name,
	            io->id, io->id_len, &new_val);
	switch (new_val.code) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		if (old_val.code != KNOT_EOK) {
			return KNOT_EOK;
		}
		break;
	default:
		return new_val.code;
	}

	// Process the value difference.
	if (old_val.code != KNOT_EOK) {
		io->data.val = &new_val;
		io->type = NEW;
		int ret = FCN(io);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else if (new_val.code != KNOT_EOK) {
		io->data.val = &old_val;
		io->type = OLD;
		int ret = FCN(io);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else if (!conf_val_equal(&old_val, &new_val)) {
		io->data.val = &old_val;
		io->type = OLD;
		int ret = FCN(io);
		if (ret != KNOT_EOK) {
			return ret;
		}

		io->data.val = &new_val;
		io->type = NEW;
		ret = FCN(io);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Reset the modified parameters.
	io->data.val = NULL;
	io->type = NONE;

	return KNOT_EOK;
}

static int diff_section(
	conf_io_t *io)
{
	// Get the value for the specified item.
	if (io->key1 != NULL) {
		return diff_item(io);
	}

	// Get the values for all items.
	for (yp_item_t *i = io->key0->sub_items; i->name != NULL; i++) {
		io->key1 = i;

		int ret = diff_item(io);

		// Reset the modified parameters.
		io->key1 = NULL;

		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int diff_iter_section(
	conf_io_t *io)
{
	// First compare the section with the old and common identifiers.
	conf_iter_t iter;
	int ret = conf_db_iter_begin(conf(), &conf()->read_txn, io->key0->name,
	                             &iter);
	switch (ret) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
		// Continue to the second step.
		ret = KNOT_EOF;
		break;
	default:
		return ret;
	}

	while (ret == KNOT_EOK) {
		ret = conf_db_iter_id(conf(), &iter, &io->id, &io->id_len);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf(), &iter);
			return ret;
		}

		ret = diff_section(io);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf(), &iter);
			return ret;
		}

		ret = conf_db_iter_next(conf(), &iter);
	}
	if (ret != KNOT_EOF) {
		return ret;
	}

	// Second compare the section with the new identifiers.
	ret = conf_db_iter_begin(conf(), conf()->io.txn, io->key0->name, &iter);
	switch (ret) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
		return KNOT_EOK;
	default:
		return ret;
	}

	while (ret == KNOT_EOK) {
		ret = conf_db_iter_id(conf(), &iter, &io->id, &io->id_len);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf(), &iter);
			return ret;
		}

		// Ignore old and common identifiers.
		ret = conf_db_get(conf(), &conf()->read_txn, io->key0->name,
		                  NULL, io->id, io->id_len, NULL);
		switch (ret) {
		case KNOT_EOK:
			ret = conf_db_iter_next(conf(), &iter);
			continue;
		case KNOT_ENOENT:
		case KNOT_YP_EINVAL_ID:
			break;
		default:
			conf_db_iter_finish(conf(), &iter);
			return ret;
		}

		ret = diff_section(io);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf(), &iter);
			return ret;
		}

		ret = conf_db_iter_next(conf(), &iter);
	}
	if (ret != KNOT_EOF) {
		return ret;
	}

	return KNOT_EOK;
}

static int diff_zone_section(
	conf_io_t *io)
{
	assert(io->key0->flags & CONF_IO_FZONE);

	if (conf()->io.zones == NULL) {
		return KNOT_EOK;
	}

	trie_it_t *it = trie_it_begin(conf()->io.zones);
	for (; !trie_it_finished(it); trie_it_next(it)) {
		io->id = (const uint8_t *)trie_it_key(it, &io->id_len);

		// Get the difference for specific zone.
		int ret = diff_section(io);
		if (ret != KNOT_EOK) {
			trie_it_free(it);
			return ret;
		}
	}
	trie_it_free(it);

	return KNOT_EOK;
}

int conf_io_diff(
	const char *key0,
	const char *key1,
	const char *id,
	conf_io_t *io)
{
	if (io == NULL) {
		return KNOT_EINVAL;
	}

	assert(conf() != NULL);

	if (conf()->io.txn == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	// Compare all sections by default.
	if (key0 == NULL) {
		for (yp_item_t *i = conf()->scheme; i->name != NULL; i++) {
			// Skip non-group item.
			if (i->type != YP_TGRP) {
				continue;
			}

			int ret = conf_io_diff(i->name + 1, key1, NULL, io);

			// Reset parameters after each section.
			io_reset_val(io, NULL, NULL, NULL, 0, false, NULL);

			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		return KNOT_EOK;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(&conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check the input.
	int ret = yp_scheme_check_str(ctx, key0, key1, id, NULL);
	if (ret != KNOT_EOK) {
		goto diff_error;
	}

	yp_node_t *node = &ctx->nodes[ctx->current];
	yp_node_t *parent = node->parent;

	// Key1 is not a group identifier.
	if (parent != NULL) {
		io_reset_val(io, parent->item, node->item, parent->id,
		             parent->id_len, false, NULL);
	// Key1 is a group identifier.
	} else if (key1 != NULL && strlen(key1) != 0) {
		assert(node->item->type == YP_TGRP &&
		       (node->item->flags & YP_FMULTI) != 0);

		io_reset_val(io, node->item, node->item->var.g.id, node->id,
		             node->id_len, true, NULL);
	// No key1 specified.
	} else {
		io_reset_val(io, node->item, NULL, node->id, node->id_len,
		             false, NULL);
	}

	// Check for a non-group item.
	if (io->key0->type != YP_TGRP) {
		ret = KNOT_ENOTSUP;
		goto diff_error;
	}

	// Compare the section with all identifiers by default.
	if ((io->key0->flags & YP_FMULTI) != 0 && io->id_len == 0) {
		// The zone section has an optimized diff.
		if (io->key0->flags & CONF_IO_FZONE) {
			// Full diff by default.
			if (!(conf()->io.flags & CONF_IO_FACTIVE)) {
				ret = diff_iter_section(io);
			// Full diff if all zones changed.
			} else if (conf()->io.flags & CONF_IO_FDIFF_ZONES) {
				ret = diff_iter_section(io);
			// Optimized diff for specific zones.
			} else {
				ret = diff_zone_section(io);
			}
		} else {
			ret = diff_iter_section(io);
		}

		goto diff_error;
	}

	// Compare the section with a possible identifier.
	ret = diff_section(io);
diff_error:
	yp_scheme_check_deinit(ctx);

	return ret;
}

static int get_section(
	knot_db_txn_t *txn,
	conf_io_t *io)
{
	conf_val_t data;

	// Get the value for the specified item.
	if (io->key1 != NULL) {
		if (!io->id_as_data) {
			// Get the item value.
			conf_db_get(conf(), txn, io->key0->name, io->key1->name,
			            io->id, io->id_len, &data);
			switch (data.code) {
			case KNOT_EOK:
				break;
			case KNOT_ENOENT:
				return KNOT_EOK;
			default:
				return data.code;
			}

			io->data.val = &data;
		}

		// Process the callback.
		int ret = FCN(io);

		// Reset the modified parameters.
		io->data.val = NULL;

		return ret;
	}

	// Get the values for all section items by default.
	for (yp_item_t *i = io->key0->sub_items; i->name != NULL; i++) {
		// Process the (first) identifier item.
		if ((io->key0->flags & YP_FMULTI) != 0 && io->key0->var.g.id == i) {
			// Check if existing identifier.
			conf_db_get(conf(), txn, io->key0->name, NULL, io->id,
			            io->id_len, &data);
			switch (data.code) {
			case KNOT_EOK:
				break;
			case KNOT_ENOENT:
				continue;
			default:
				return data.code;
			}

			io->key1 = i;
			io->id_as_data = true;

			// Process the callback.
			int ret = FCN(io);

			// Reset the modified parameters.
			io->key1 = NULL;
			io->id_as_data = false;

			if (ret != KNOT_EOK) {
				return ret;
			}

			continue;
		}

		// Get the item value.
		conf_db_get(conf(), txn, io->key0->name, i->name, io->id,
		            io->id_len, &data);
		switch (data.code) {
		case KNOT_EOK:
			break;
		case KNOT_ENOENT:
			continue;
		default:
			return data.code;
		}

		io->key1 = i;
		io->data.val = &data;

		// Process the callback.
		int ret = FCN(io);

		// Reset the modified parameters.
		io->key1 = NULL;
		io->data.val = NULL;

		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int conf_io_get(
	const char *key0,
	const char *key1,
	const char *id,
	bool get_current,
	conf_io_t *io)
{
	if (io == NULL) {
		return KNOT_EINVAL;
	}

	assert(conf() != NULL);

	if (conf()->io.txn == NULL && !get_current) {
		return KNOT_TXN_ENOTEXISTS;
	}

	// List all sections by default.
	if (key0 == NULL) {
		for (yp_item_t *i = conf()->scheme; i->name != NULL; i++) {
			// Skip non-group item.
			if (i->type != YP_TGRP) {
				continue;
			}

			int ret = conf_io_get(i->name + 1, key1, NULL,
			                      get_current, io);
			// Reset parameters after each section.
			io_reset_val(io, NULL, NULL, NULL, 0, false, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		return KNOT_EOK;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(&conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check the input.
	int ret = yp_scheme_check_str(ctx, key0, key1, id, NULL);
	if (ret != KNOT_EOK) {
		goto get_error;
	}

	yp_node_t *node = &ctx->nodes[ctx->current];
	yp_node_t *parent = node->parent;

	// Key1 is not a group identifier.
	if (parent != NULL) {
		io_reset_val(io, parent->item, node->item, parent->id,
		             parent->id_len, false, NULL);
	// Key1 is a group identifier.
	} else if (key1 != NULL && strlen(key1) != 0) {
		assert(node->item->type == YP_TGRP &&
		       (node->item->flags & YP_FMULTI) != 0);

		io_reset_val(io, node->item, node->item->var.g.id, node->id,
		             node->id_len, true, NULL);
	// No key1 specified.
	} else {
		io_reset_val(io, node->item, NULL, node->id, node->id_len, false,
		             NULL);
	}

	knot_db_txn_t *txn = get_current ? &conf()->read_txn : conf()->io.txn;

	// Check for a non-group item.
	if (io->key0->type != YP_TGRP) {
		ret = KNOT_ENOTSUP;
		goto get_error;
	}

	// List the section with all identifiers by default.
	if ((io->key0->flags & YP_FMULTI) != 0 && io->id_len == 0) {
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf(), txn, io->key0->name, &iter);
		switch (ret) {
		case KNOT_EOK:
			break;
		case KNOT_ENOENT:
			ret = KNOT_EOK;
			goto get_error;
		default:
			goto get_error;
		}

		while (ret == KNOT_EOK) {
			// Set the section identifier.
			ret = conf_db_iter_id(conf(), &iter, &io->id, &io->id_len);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto get_error;
			}

			ret = get_section(txn, io);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto get_error;
			}

			ret = conf_db_iter_next(conf(), &iter);
		}

		ret = KNOT_EOK;
		goto get_error;
	}

	// List the section with a possible identifier.
	ret = get_section(txn, io);
get_error:
	yp_scheme_check_deinit(ctx);

	return ret;
}

static void upd_changes(
	const conf_io_t *io,
	conf_io_type_t type,
	yp_flag_t flags,
	bool any_id)
{
	// Update common flags.
	conf()->io.flags |= flags;

	// Return if not important change.
	if (type == CONF_IO_TNONE) {
		return;
	}

	// Update reference item.
	if (flags & CONF_IO_FREF) {
		// Expected an identifier, which cannot be changed.
		assert(type != CONF_IO_TCHANGE);

		// Re-check and reload all zones if a reference has been removed.
		if (type == CONF_IO_TUNSET) {
			conf()->io.flags |= CONF_IO_FCHECK_ZONES | CONF_IO_FRLD_ZONES;
		}
		return;
	// Return if no specific zone operation.
	} else if (!(flags & CONF_IO_FZONE)) {
		return;
	}

	// Don't process each zone individually, process all instead.
	if (any_id) {
		// Diff all zone changes.
		conf()->io.flags |= CONF_IO_FCHECK_ZONES | CONF_IO_FDIFF_ZONES;

		// Reload just with important changes.
		if (flags & CONF_IO_FRLD_ZONE) {
			conf()->io.flags |= CONF_IO_FRLD_ZONES;
		}
		return;
	}

	// Prepare zone changes storage if it doesn't exist.
	trie_t *zones = conf()->io.zones;
	if (zones == NULL) {
		zones = trie_create(conf()->mm);
		if (zones == NULL) {
			return;
		}
		conf()->io.zones = zones;
	}

	// Get zone status or create new.
	trie_val_t *val = trie_get_ins(zones, (const char *)io->id, io->id_len);
	conf_io_type_t *current = (conf_io_type_t *)val;

	switch (type) {
	case CONF_IO_TSET:
		// Revert remove zone, but don't remove (probably changed).
		if (*current & CONF_IO_TUNSET) {
			*current &= ~CONF_IO_TUNSET;
		} else {
			// Must be a new zone.
			assert(*current == CONF_IO_TNONE);
			// Mark added zone.
			*current = type;
		}
		break;
	case CONF_IO_TUNSET:
		if (*current & CONF_IO_TSET) {
			// Remove inserted zone -> no change.
			trie_del(zones, (const char *)io->id, io->id_len, NULL);
		} else {
			// Remove existing zone.
			*current |= type;
		}
		break;
	case CONF_IO_TCHANGE:
		*current |= type;
		// Mark zone to reload if required.
		if (flags & CONF_IO_FRLD_ZONE) {
			*current |= CONF_IO_TRELOAD;
		}
		break;
	case CONF_IO_TRELOAD:
	default:
		assert(0);
	}
}

static int set_item(
	conf_io_t *io)
{
	int ret = conf_db_set(conf(), conf()->io.txn, io->key0->name,
	                      (io->key1 != NULL) ? io->key1->name : NULL,
	                      io->id, io->id_len, io->data.bin, io->data.bin_len);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Postpone group callbacks to config check.
	if (io->key0->type == YP_TGRP && io->id_len == 0) {
		return KNOT_EOK;
	}

	knotd_conf_check_extra_t extra = {
		.conf = conf(),
		.txn = conf()->io.txn
	};
	knotd_conf_check_args_t args = {
		.item = (io->key1 != NULL) ? io->key1 :
		         ((io->id_len == 0) ? io->key0 : io->key0->var.g.id),
		.id = io->id,
		.id_len = io->id_len,
		.data = io->data.bin,
		.data_len = io->data.bin_len,
		.extra = &extra
	};

	// Call the item callbacks (include, item check, mod-id check).
	ret = conf_exec_callbacks(&args);
	if (ret != KNOT_EOK) {
		CONF_LOG(LOG_DEBUG, "item '%s' (%s)", args.item->name + 1,
		         args.err_str != NULL ? args.err_str : knot_strerror(ret));
	}

	return ret;
}

int conf_io_set(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data)
{
	assert(conf() != NULL);

	if (conf()->io.txn == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	// At least key0 must be specified.
	if (key0 == NULL) {
		return KNOT_EINVAL;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(&conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check the input.
	int ret = yp_scheme_check_str(ctx, key0, key1, id, data);
	if (ret != KNOT_EOK) {
		goto set_error;
	}

	yp_node_t *node = &ctx->nodes[ctx->current];
	yp_node_t *parent = node->parent;

	yp_flag_t upd_flags = node->item->flags;
	conf_io_type_t upd_type = CONF_IO_TNONE;

	conf_io_t io = { NULL };

	// Key1 is not a group identifier.
	if (parent != NULL) {
		if (node->data_len == 0) {
			ret = KNOT_YP_ENODATA;
			goto set_error;
		}
		upd_type = CONF_IO_TCHANGE;
		upd_flags |= parent->item->flags;
		io_reset_bin(&io, parent->item, node->item, parent->id,
		             parent->id_len, node->data, node->data_len);
	// A group identifier or whole group.
	} else if (node->item->type == YP_TGRP) {
		upd_type = CONF_IO_TSET;
		if ((node->item->flags & YP_FMULTI) != 0) {
			if (node->id_len == 0) {
				ret = KNOT_YP_ENOID;
				goto set_error;
			}
			upd_flags |= node->item->var.g.id->flags;
		} else {
			ret = KNOT_ENOTSUP;
			goto set_error;
		}
		assert(node->data_len == 0);
		io_reset_bin(&io, node->item, NULL, node->id, node->id_len,
		             NULL, 0);
	// A non-group item with data (include).
	} else if (node->data_len > 0) {
		io_reset_bin(&io, node->item, NULL, NULL, 0, node->data,
		             node->data_len);
	} else {
		ret = KNOT_YP_ENODATA;
		goto set_error;
	}

	// Set the item for all identifiers by default.
	if (io.key0->type == YP_TGRP && io.key1 != NULL &&
	    (io.key0->flags & YP_FMULTI) != 0 && io.id_len == 0) {
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf(), conf()->io.txn, io.key0->name,
		                         &iter);
		switch (ret) {
		case KNOT_EOK:
			break;
		case KNOT_ENOENT:
			ret = KNOT_EOK;
			goto set_error;
		default:
			goto set_error;
		}

		while (ret == KNOT_EOK) {
			// Get the identifier.
			ret = conf_db_iter_id(conf(), &iter, &io.id, &io.id_len);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto set_error;
			}

			// Set the data.
			ret = set_item(&io);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto set_error;
			}

			ret = conf_db_iter_next(conf(), &iter);
		}
		if (ret != KNOT_EOF) {
			goto set_error;
		}

		upd_changes(&io, upd_type, upd_flags, true);

		ret = KNOT_EOK;
		goto set_error;
	}

	// Set the item with a possible identifier.
	ret = set_item(&io);

	if (ret == KNOT_EOK) {
		upd_changes(&io, upd_type, upd_flags, false);
	}
set_error:
	yp_scheme_check_deinit(ctx);

	return ret;
}

static int unset_section_data(
	conf_io_t *io)
{
	// Unset the value for the specified item.
	if (io->key1 != NULL) {
		return conf_db_unset(conf(), conf()->io.txn, io->key0->name,
		                     io->key1->name, io->id, io->id_len,
		                     io->data.bin, io->data.bin_len, false);
	}

	// Unset the whole section by default.
	for (yp_item_t *i = io->key0->sub_items; i->name != NULL; i++) {
		// Skip the identifier item.
		if ((io->key0->flags & YP_FMULTI) != 0 && io->key0->var.g.id == i) {
			continue;
		}

		int ret = conf_db_unset(conf(), conf()->io.txn, io->key0->name,
		                        i->name, io->id, io->id_len, io->data.bin,
		                        io->data.bin_len, false);
		switch (ret) {
		case KNOT_EOK:
		case KNOT_ENOENT:
			continue;
		default:
			return ret;
		}
	}

	return KNOT_EOK;
}

static int unset_section(
	const yp_item_t *key0)
{
	// Unset the section items.
	for (yp_item_t *i = key0->sub_items; i->name != NULL; i++) {
		// Skip the identifier item.
		if ((key0->flags & YP_FMULTI) != 0 && key0->var.g.id == i) {
			continue;
		}

		int ret = conf_db_unset(conf(), conf()->io.txn, key0->name,
		                        i->name, NULL, 0, NULL, 0, true);
		switch (ret) {
		case KNOT_EOK:
		case KNOT_ENOENT:
			continue;
		default:
			return ret;
		}
	}

	// Unset the section.
	int ret = conf_db_unset(conf(), conf()->io.txn, key0->name, NULL, NULL,
	                        0, NULL, 0, false);
	switch (ret) {
	case KNOT_EOK:
	case KNOT_ENOENT:
		return KNOT_EOK;
	default:
		return ret;
	}
}

int conf_io_unset(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data)
{
	assert(conf() != NULL);

	if (conf()->io.txn == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	// Unset all sections by default.
	if (key0 == NULL) {
		for (yp_item_t *i = conf()->scheme; i->name != NULL; i++) {
			// Skip non-group item.
			if (i->type != YP_TGRP) {
				continue;
			}

			int ret = conf_io_unset(i->name + 1, key1, NULL, NULL);
			switch (ret) {
			case KNOT_EOK:
			case KNOT_ENOENT:
				break;
			default:
				return ret;
			}
		}

		return KNOT_EOK;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(&conf()->scheme);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Check the input.
	int ret = yp_scheme_check_str(ctx, key0, key1, id, data);
	if (ret != KNOT_EOK) {
		goto unset_error;
	}

	yp_node_t *node = &ctx->nodes[ctx->current];
	yp_node_t *parent = node->parent;

	yp_flag_t upd_flags = node->item->flags;
	conf_io_type_t upd_type = CONF_IO_TNONE;

	conf_io_t io = { NULL };

	// Key1 is not a group identifier.
	if (parent != NULL) {
		upd_type = CONF_IO_TCHANGE;
		upd_flags |= parent->item->flags;
		io_reset_bin(&io, parent->item, node->item, parent->id,
		             parent->id_len, node->data, node->data_len);
	// A group identifier or whole group.
	} else if (node->item->type == YP_TGRP) {
		upd_type = CONF_IO_TUNSET;
		if ((node->item->flags & YP_FMULTI) != 0) {
			upd_flags |= node->item->var.g.id->flags;
		}
		assert(node->data_len == 0);
		io_reset_bin(&io, node->item, NULL, node->id, node->id_len,
		             NULL, 0);
	// A non-group item (include).
	} else {
		ret = KNOT_ENOTSUP;
		goto unset_error;
	}

	// Unset the section with all identifiers by default.
	if ((io.key0->flags & YP_FMULTI) != 0 && io.id_len == 0) {
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf(), conf()->io.txn, io.key0->name,
		                         &iter);
		switch (ret) {
		case KNOT_EOK:
			break;
		case KNOT_ENOENT:
			ret = KNOT_EOK;
			goto unset_error;
		default:
			goto unset_error;
		}

		while (ret == KNOT_EOK) {
			// Get the identifier.
			ret = conf_db_iter_id(conf(), &iter, &io.id, &io.id_len);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto unset_error;
			}

			// Unset the section data.
			ret = unset_section_data(&io);
			switch (ret) {
			case KNOT_EOK:
			case KNOT_ENOENT:
				break;
			default:
				conf_db_iter_finish(conf(), &iter);
				goto unset_error;
			}

			ret = conf_db_iter_next(conf(), &iter);
		}
		if (ret != KNOT_EOF) {
			goto unset_error;
		}

		if (io.key1 == NULL) {
			// Unset all identifiers.
			ret = conf_db_iter_begin(conf(), conf()->io.txn,
			                         io.key0->name, &iter);
			switch (ret) {
			case KNOT_EOK:
				break;
			case KNOT_ENOENT:
				ret = KNOT_EOK;
				goto unset_error;
			default:
				goto unset_error;
			}

			while (ret == KNOT_EOK) {
				ret = conf_db_iter_del(conf(), &iter);
				if (ret != KNOT_EOK) {
					conf_db_iter_finish(conf(), &iter);
					goto unset_error;
				}

				ret = conf_db_iter_next(conf(), &iter);
			}
			if (ret != KNOT_EOF) {
				goto unset_error;
			}

			// Unset the section.
			ret = unset_section(io.key0);
			if (ret != KNOT_EOK) {
				goto unset_error;
			}
		}

		upd_changes(&io, upd_type, upd_flags, true);

		ret = KNOT_EOK;
		goto unset_error;
	}

	// Unset the section data.
	ret = unset_section_data(&io);
	if (ret != KNOT_EOK) {
		goto unset_error;
	}

	if (io.key1 == NULL) {
		// Unset the identifier.
		if (io.id_len != 0) {
			ret = conf_db_unset(conf(), conf()->io.txn, io.key0->name,
			                    NULL, io.id, io.id_len, NULL, 0, false);
			if (ret != KNOT_EOK) {
				goto unset_error;
			}
		// Unset the section.
		} else {
			ret = unset_section(io.key0);
			if (ret != KNOT_EOK) {
				goto unset_error;
			}
		}
	}

	if (ret == KNOT_EOK) {
		upd_changes(&io, upd_type, upd_flags, false);
	}
unset_error:
	yp_scheme_check_deinit(ctx);

	return ret;
}

static int check_section(
	const yp_item_t *group,
	const uint8_t *id,
	size_t id_len,
	conf_io_t *io)
{
	knotd_conf_check_extra_t extra = {
		.conf = conf(),
		.txn = conf()->io.txn,
		.check = true
	};
	knotd_conf_check_args_t args = {
		.id = id,
		.id_len = id_len,
		.extra = &extra
	};

	bool non_empty = false;

	for (yp_item_t *item = group->sub_items; item->name != NULL; item++) {
		args.item = item;

		// Check the identifier.
		if ((group->flags & YP_FMULTI) != 0 && group->var.g.id == item) {
			io->error.code = conf_exec_callbacks(&args);
			if (io->error.code != KNOT_EOK) {
				io_reset_val(io, group, item, NULL, 0, false, NULL);
				goto check_section_error;
			}
			continue;
		}

		// Get the item value.
		conf_val_t bin;
		conf_db_get(conf(), conf()->io.txn, group->name, item->name, id,
		            id_len, &bin);
		if (bin.code == KNOT_ENOENT) {
			continue;
		} else if (bin.code != KNOT_EOK) {
			return bin.code;
		}

		non_empty = true;

		// Check the item value(s).
		size_t values = conf_val_count(&bin);
		for (size_t i = 1; i <= values; i++) {
			conf_val(&bin);
			args.data = bin.data;
			args.data_len = bin.len;

			io->error.code = conf_exec_callbacks(&args);
			if (io->error.code != KNOT_EOK) {
				io_reset_val(io, group, item, id, id_len, false,
				             &bin);
				io->data.index = i;
				goto check_section_error;
			}

			if (values > 1) {
				conf_val_next(&bin);
			}
		}
	}

	// Check the whole section if not empty.
	if (id != NULL || non_empty) {
		args.item = group;
		args.data = NULL;
		args.data_len = 0;

		io->error.code = conf_exec_callbacks(&args);
		if (io->error.code != KNOT_EOK) {
			io_reset_val(io, group, NULL, id, id_len, false, NULL);
			goto check_section_error;
		}
	}

	return KNOT_EOK;

check_section_error:
	io->error.str = args.err_str;
	int ret = FCN(io);
	if (ret == KNOT_EOK) {
		return io->error.code;
	}
	return ret;
}

static int check_iter_section(
	const yp_item_t *item,
	conf_io_t *io)
{
	// Iterate over all identifiers.
	conf_iter_t iter;
	int ret = conf_db_iter_begin(conf(), conf()->io.txn, item->name, &iter);
	switch (ret) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
		return KNOT_EOK;
	default:
		return ret;
	}

	while (ret == KNOT_EOK) {
		size_t id_len;
		const uint8_t *id;
		ret = conf_db_iter_id(conf(), &iter, &id, &id_len);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf(), &iter);
			return ret;
		}

		// Check specific section item.
		ret = check_section(item, id, id_len, io);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf(), &iter);
			return ret;
		}

		ret = conf_db_iter_next(conf(), &iter);
	}
	if (ret != KNOT_EOF) {
		return ret;
	}

	return KNOT_EOK;
}

static int check_zone_section(
	const yp_item_t *item,
	conf_io_t *io)
{
	assert(item->flags & CONF_IO_FZONE);

	if (conf()->io.zones == NULL) {
		return KNOT_EOK;
	}

	trie_it_t *it = trie_it_begin(conf()->io.zones);
	for (; !trie_it_finished(it); trie_it_next(it)) {
		size_t id_len;
		const uint8_t *id = (const uint8_t *)trie_it_key(it, &id_len);

		conf_io_type_t type = (conf_io_type_t)(*trie_it_val(it));
		if (type == CONF_IO_TUNSET) {
			// Nothing to check.
			continue;
		}

		// Check specific zone.
		int ret = check_section(item, id, id_len, io);
		if (ret != KNOT_EOK) {
			trie_it_free(it);
			return ret;
		}
	}
	trie_it_free(it);

	return KNOT_EOK;
}

int conf_io_check(
	conf_io_t *io)
{
	if (io == NULL) {
		return KNOT_EINVAL;
	}

	assert(conf() != NULL);

	if (conf()->io.txn == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	int ret;

	// Iterate over the scheme.
	for (yp_item_t *item = conf()->scheme; item->name != NULL; item++) {
		// Skip non-group items (include).
		if (item->type != YP_TGRP) {
			continue;
		}

		// Check simple group without identifiers.
		if ((item->flags & YP_FMULTI) == 0) {
			ret = check_section(item, NULL, 0, io);
			if (ret != KNOT_EOK) {
				goto check_error;
			}
			continue;
		}

		// The zone section has an optimized check.
		if (item->flags & CONF_IO_FZONE) {
			// Full check by default.
			if (!(conf()->io.flags & CONF_IO_FACTIVE)) {
				ret = check_iter_section(item, io);
			// Full check if all zones changed.
			} else if (conf()->io.flags & CONF_IO_FCHECK_ZONES) {
				ret = check_iter_section(item, io);
			// Optimized check for specific zones.
			} else {
				ret = check_zone_section(item, io);
			}
		} else {
			ret = check_iter_section(item, io);
		}
		if (ret != KNOT_EOK) {
			goto check_error;
		}
	}

	ret = KNOT_EOK;
check_error:
	conf_mod_load_purge(conf(), true);

	return ret;
}
