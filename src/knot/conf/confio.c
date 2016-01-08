/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <pthread.h>

#include "knot/conf/confdb.h"
#include "knot/conf/confio.h"
#include "knot/conf/tools.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/string.h"
#include "contrib/openbsd/strlcat.h"

#define FCN(io)	(io->fcn != NULL) ? io->fcn(io) : KNOT_EOK

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
		return KNOT_CONF_ETXN;
	} else if (conf()->io.txn == NULL && child) {
		return KNOT_CONF_ENOTXN;
	}

	knot_db_txn_t *parent = conf()->io.txn;
	knot_db_txn_t *txn = (parent == NULL) ? conf()->io.txn_stack : parent + 1;
	if (txn >= conf()->io.txn_stack + CONF_MAX_TXN_DEPTH) {
		return KNOT_CONF_EMANYTXN;
	}

	// Start the writing transaction.
	int ret = knot_db_lmdb_txn_begin(conf()->db, txn, parent, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	conf()->io.txn = txn;

	return KNOT_EOK;
}

int conf_io_commit(
	bool child)
{
	assert(conf() != NULL);

	if (conf()->io.txn == NULL ||
	    (child && conf()->io.txn == conf()->io.txn_stack)) {
		return KNOT_CONF_ENOTXN;
	}

	knot_db_txn_t *txn = child ? conf()->io.txn : conf()->io.txn_stack;

	// Commit the writing transaction.
	int ret = conf()->api->txn_commit(txn);
	conf()->io.txn = child ? txn - 1 : NULL;
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Don't reload the configuration if child transaction.
	if (child) {
		return KNOT_EOK;
	}

	// Clone new configuration.
	conf_t *new_conf = NULL;
	ret = conf_clone(&new_conf);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update read-only transaction.
	new_conf->api->txn_abort(&new_conf->read_txn);
	ret = new_conf->api->txn_begin(new_conf->db, &new_conf->read_txn,
	                               KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		conf_free(new_conf);
		return ret;
	}

	// Run post-open config operations.
	ret = conf_post_open(new_conf);
	if (ret != KNOT_EOK) {
		conf_free(new_conf);
		return ret;
	}

	// Update to the new config.
	conf_update(new_conf);

	return KNOT_EOK;
}

int conf_io_abort(
	bool child)
{
	assert(conf() != NULL);

	if (conf()->io.txn == NULL ||
	    (child && conf()->io.txn == conf()->io.txn_stack)) {
		return KNOT_CONF_ENOTXN;
	}

	knot_db_txn_t *txn = child ? conf()->io.txn : conf()->io.txn_stack;

	// Abort the writing transaction.
	conf()->api->txn_abort(txn);
	conf()->io.txn = child ? txn - 1 : NULL;

	return KNOT_EOK;
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

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
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
		return KNOT_CONF_ENOTXN;
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

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
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
		// First compare the section with the old and common identifiers.
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf(), &conf()->read_txn,
		                         io->key0->name, &iter);
		switch (ret) {
		case KNOT_EOK:
		case KNOT_ENOENT:
			break;
		default:
			goto diff_error;
		}

		while (ret == KNOT_EOK) {
			// Set the section identifier.
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

		// Second compare the section with the new identifiers.
		ret = conf_db_iter_begin(conf(), conf()->io.txn, io->key0->name,
		                         &iter);
		switch (ret) {
		case KNOT_EOK:
		case KNOT_ENOENT:
			break;
		default:
			goto diff_error;
		}

		while (ret == KNOT_EOK) {
			// Set the section identifier.
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

		ret = KNOT_EOK;
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
		return KNOT_CONF_ENOTXN;
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

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
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
	if (io->key0->type != YP_TGRP) {
		conf_check_t args = {
			.conf = conf(),
			.txn = conf()->io.txn,
			.item = (io->key1 != NULL) ? io->key1 : io->key0,
			.id = io->id,
			.id_len = io->id_len,
			.data = io->data.bin,
			.data_len = io->data.bin_len
		};

		// Call the item callbacks.
		io->error.code = conf_exec_callbacks(args.item, &args);
		if (io->error.code != KNOT_EOK) {
			io->error.str = args.err_str;
			ret = FCN(io);
			if (ret == KNOT_EOK) {
				ret = io->error.code;
			}
		}
	}

	return ret;
}

int conf_io_set(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data,
	conf_io_t *io)
{
	if (io == NULL) {
		return KNOT_EINVAL;
	}

	assert(conf() != NULL);

	if (conf()->io.txn == NULL) {
		return KNOT_CONF_ENOTXN;
	}

	// At least key0 must be specified.
	if (key0 == NULL) {
		return KNOT_EINVAL;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
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

	// Key1 is not a group identifier.
	if (parent != NULL) {
		io_reset_bin(io, parent->item, node->item, parent->id,
		             parent->id_len, node->data, node->data_len);
	// No key1 but a group identifier.
	} else if (node->id_len != 0) {
		assert(node->item->type == YP_TGRP &&
		       (node->item->flags & YP_FMULTI) != 0);
		assert(node->data_len == 0);

		io_reset_bin(io, node->item, node->item->var.g.id, node->id,
		             node->id_len, NULL, 0);
	// Ensure some data for non-group items (include).
	} else if (node->item->type == YP_TGRP || node->data_len != 0) {
		io_reset_bin(io, node->item, NULL, node->id, node->id_len,
		             node->data, node->data_len);
	// Non-group without data.
	} else {
		ret = KNOT_YP_ENODATA;
		goto set_error;
	}

	// Set the item for all identifiers by default.
	if (io->key0->type == YP_TGRP && io->key1 != NULL &&
	    (io->key0->flags & YP_FMULTI) != 0 && io->id_len == 0) {
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf(), conf()->io.txn, io->key0->name,
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
			ret = conf_db_iter_id(conf(), &iter, &io->id, &io->id_len);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto set_error;
			}

			// Set the data.
			ret = set_item(io);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto set_error;
			}

			ret = conf_db_iter_next(conf(), &iter);
		}
		if (ret != KNOT_EOF) {
			goto set_error;
		}

		ret = KNOT_EOK;
		goto set_error;
	}

	// Set the item with a possible identifier.
	ret = set_item(io);
set_error:
	yp_scheme_check_deinit(ctx);

	return ret;
}

static int unset_section_data(
	conf_io_t *io)
{
	// Delete the value for the specified item.
	if (io->key1 != NULL) {
		return conf_db_unset(conf(), conf()->io.txn, io->key0->name,
		                     io->key1->name, io->id, io->id_len,
		                     io->data.bin, io->data.bin_len, false);
	}

	// Delete the whole section by default.
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
	// Delete the section items.
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

	// Delete the section.
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
		return KNOT_CONF_ENOTXN;
	}

	// Delete all sections by default.
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

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf()->scheme);
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

	conf_io_t io = { NULL };

	if (parent != NULL) {
		io_reset_bin(&io, parent->item, node->item, parent->id,
		             parent->id_len, node->data, node->data_len);
	} else {
		io_reset_bin(&io, node->item, NULL, node->id, node->id_len,
		             node->data, node->data_len);
	}

	// Check for a non-group item.
	if (io.key0->type != YP_TGRP) {
		ret = KNOT_ENOTSUP;
		goto unset_error;
	}

	// Delete the section with all identifiers by default.
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

			// Delete the section data.
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
			// Delete all identifiers.
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

			// Delete the section.
			ret = unset_section(io.key0);
			if (ret != KNOT_EOK) {
				goto unset_error;
			}
		}

		ret = KNOT_EOK;
		goto unset_error;
	}

	// Delete the section data.
	ret = unset_section_data(&io);
	if (ret != KNOT_EOK) {
		goto unset_error;
	}

	if (io.key1 == NULL) {
		// Delete the identifier.
		if (io.id_len != 0) {
			ret = conf_db_unset(conf(), conf()->io.txn, io.key0->name,
			                    NULL, io.id, io.id_len, NULL, 0, false);
			if (ret != KNOT_EOK) {
				goto unset_error;
			}
		// Delete the section.
		} else {
			ret = unset_section(io.key0);
			if (ret != KNOT_EOK) {
				goto unset_error;
			}
		}
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
	conf_check_t args = {
		.conf = conf(),
		.txn = conf()->io.txn,
		.id = id,
		.id_len = id_len
	};

	bool non_empty = false;

	for (yp_item_t *item = group->sub_items; item->name != NULL; item++) {
		args.item = item;

		// Check the identifier.
		if ((group->flags & YP_FMULTI) != 0 && group->var.g.id == item) {
			io->error.code = conf_exec_callbacks(item, &args);
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

			io->error.code = conf_exec_callbacks(item, &args);
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

		io->error.code = conf_exec_callbacks(group, &args);
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

int conf_io_check(
	conf_io_t *io)
{
	if (io == NULL) {
		return KNOT_EINVAL;
	}

	assert(conf() != NULL);

	if (conf()->io.txn == NULL) {
		return KNOT_CONF_ENOTXN;
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

		// Iterate over all identifiers.
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf(), conf()->io.txn, item->name, &iter);
		switch (ret) {
		case KNOT_EOK:
			break;
		case KNOT_ENOENT:
			continue;
		default:
			goto check_error;
		}

		while (ret == KNOT_EOK) {
			const uint8_t *id;
			size_t id_len;
			ret = conf_db_iter_id(conf(), &iter, &id, &id_len);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto check_error;
			}

			// Check group with identifiers.
			ret = check_section(item, id, id_len, io);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf(), &iter);
				goto check_error;
			}

			ret = conf_db_iter_next(conf(), &iter);
		}
		if (ret != KNOT_EOF) {
			goto check_error;
		}
	}

	ret = KNOT_EOK;
check_error:

	return ret;
}

char *conf_io_txt_key(
	conf_io_t *io)
{
	if (io == NULL || io->key0 == NULL) {
		return NULL;
	}

	char id[KNOT_DNAME_TXT_MAXLEN + 1] = "\0";
	size_t id_len = sizeof(id);

	// Get the textual item id.
	if (io->id_len > 0 && !io->id_as_data) {
		if (yp_item_to_txt(io->key0->var.g.id, io->id, io->id_len, id,
		                   &id_len, YP_SNOQUOTE) != KNOT_EOK) {
			return NULL;
		}
	}

	// Get the item prefix.
	const char *prefix = "";
	switch (io->type) {
	case NEW:
		prefix = "+";
		break;
	case OLD:
		prefix = "-";
		break;
	default:
		break;
	}

	// Format the item key.
	return sprintf_alloc(
		"%s%.*s%s%.*s%s%s%.*s",
		prefix, (int)io->key0->name[0], io->key0->name + 1,
		(io->id_len > 0 && !io->id_as_data ? "[" : ""),
		(io->id_len > 0 && !io->id_as_data ? (int)id_len : 0), id,
		(io->id_len > 0 && !io->id_as_data ? "]" : ""),
		(io->key1 != NULL ? "." : ""),
		(io->key1 != NULL ? (int)io->key1->name[0] : 0),
		(io->key1 != NULL ? io->key1->name + 1 : ""));
}

static int append_data(
	const yp_item_t *item,
	const uint8_t *bin,
	size_t bin_len,
	char *out,
	size_t out_len)
{
	char buf[YP_MAX_TXT_DATA_LEN + 1] = "\0";
	size_t buf_len = sizeof(buf);

	int ret = yp_item_to_txt(item, bin, bin_len, buf, &buf_len, YP_SNONE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (strlcat(out, buf, out_len) >= out_len) {
		return KNOT_ESPACE;
	}

	return KNOT_EOK;
}

char *conf_io_txt_data(
	conf_io_t *io)
{
	if (io == NULL || io->key0 == NULL) {
		return NULL;
	}

	char out[YP_MAX_TXT_DATA_LEN + 1] = "\0";

	// Return the item identifier as the item data.
	if (io->id_as_data) {
		if (append_data(io->key0->var.g.id, io->id, io->id_len, out,
		                sizeof(out)) != KNOT_EOK) {
			return NULL;
		}

		return strdup(out);
	}

	// Check for no data.
	if (io->data.val == NULL && io->data.bin == NULL) {
		return NULL;
	}

	const yp_item_t *item = (io->key1 != NULL) ? io->key1 : io->key0;

	// Format explicit binary data value.
	if (io->data.bin != NULL) {
		if (append_data(item, io->data.bin, io->data.bin_len, out,
		                sizeof(out)) != KNOT_EOK) {
			return NULL;
		}
	// Format multivalued item data.
	} else if (item->flags & YP_FMULTI) {
		size_t values = conf_val_count(io->data.val);
		for (size_t i = 0; i < values; i++) {
			// Skip other values if known index (counted from 1).
			if (io->data.index > 0 &&
			    io->data.index != i + 1) {
				conf_val_next(io->data.val);
				continue;
			}

			if (i > 0) {
				if (strlcat(out, " ", sizeof(out)) >= sizeof(out)) {
					return NULL;
				}
			}

			conf_val(io->data.val);
			if (append_data(item, io->data.val->data, io->data.val->len,
			                out, sizeof(out)) != KNOT_EOK) {
				return NULL;
			}

			conf_val_next(io->data.val);
		}
	// Format singlevalued item data.
	} else {
		conf_val(io->data.val);
		if (append_data(item, io->data.val->data, io->data.val->len, out,
		                sizeof(out)) != KNOT_EOK) {
			return NULL;
		}
	}

	return strdup(out);
}
