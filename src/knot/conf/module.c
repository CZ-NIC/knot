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

#include <dlfcn.h>
#include <glob.h>
#include <sys/stat.h>
#include <urcu.h>

#include "knot/conf/conf.h"
#include "knot/conf/confio.h"
#include "knot/conf/module.h"
#include "knot/common/log.h"
#include "knot/modules/static_modules.h"
#include "knot/nameserver/query_module.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/string.h"

#define LIB_EXTENSION ".so"

dynarray_define(mod, module_t *, DYNARRAY_VISIBILITY_PUBLIC, 16)
dynarray_define(old_schema, yp_item_t *, DYNARRAY_VISIBILITY_PUBLIC, 16)

static module_t STATIC_MODULES[] = {
	STATIC_MODULES_INIT
	{ NULL }
};

module_t *conf_mod_find(
	conf_t *conf,
	const char *name,
	size_t len,
	bool temporary)
{
	if (conf == NULL || name == NULL) {
		return NULL;
	}

	// First, search in static modules.
	for (module_t *mod = STATIC_MODULES; mod->api != NULL; mod++) {
		if (strncmp(name, mod->api->name, len) == 0) {
			return mod;
		}
	}

	// Second, search in dynamic modules.
	dynarray_foreach(mod, module_t *, module, conf->modules) {
		if ((*module) != NULL && (*module)->temporary == temporary &&
		    strncmp(name, (*module)->api->name, len) == 0) {
			return (*module);
		}
	}

	return NULL;
}

static int mod_load(
	conf_t *conf,
	module_t *mod)
{
	static const yp_item_t module_common[] = {
		{ C_ID,      YP_TSTR,  YP_VNONE, CONF_IO_FREF },
		{ C_COMMENT, YP_TSTR,  YP_VNONE },
		{ NULL }
	};

	yp_item_t *sub_items = NULL;

	int ret;
	if (mod->api->config != NULL) {
		ret = yp_schema_merge(&sub_items, module_common, mod->api->config);
	} else {
		ret = yp_schema_copy(&sub_items, module_common);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Synthesise module config section name. */
	const size_t name_len = strlen(mod->api->name);
	if (name_len > YP_MAX_ITEM_NAME_LEN) {
		return KNOT_YP_EINVAL_ITEM;
	}
	char name[1 + YP_MAX_ITEM_NAME_LEN + 1];
	name[0] = name_len;
	memcpy(name + 1, mod->api->name, name_len + 1);

	const yp_item_t schema[] = {
		{ name, YP_TGRP, YP_VGRP = { sub_items },
		        YP_FALLOC | YP_FMULTI | CONF_IO_FRLD_MOD | CONF_IO_FRLD_ZONES },
		{ NULL }
	};

	yp_item_t *merged = NULL;
	ret = yp_schema_merge(&merged, conf->schema, schema);
	yp_schema_free(sub_items);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update configuration schema (with lazy free).
	yp_item_t **current_schema = &conf->schema;
	yp_item_t *old_schema = rcu_xchg_pointer(current_schema, merged);
	synchronize_rcu();
	old_schema_dynarray_add(&conf->old_schemas, &old_schema);

	return KNOT_EOK;
}

int conf_mod_load_common(
	conf_t *conf)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	// First, load static modules.
	for (module_t *mod = STATIC_MODULES; mod->api != NULL; mod++) {
		ret = mod_load(conf, mod);
		if (ret != KNOT_EOK) {
			break;
		}

		log_debug("module '%s', loaded static", mod->api->name);
	}

	// Second, try to load implicit shared modules if configured.
	if (strlen(MODULE_DIR) > 0) {
		struct stat path_stat;
		glob_t glob_buf = { 0 };

		char *path = sprintf_alloc("%s/*%s", MODULE_DIR, LIB_EXTENSION);
		if (path == NULL) {
			ret = KNOT_ENOMEM;
		} else if (stat(MODULE_DIR, &path_stat) != 0 ||
		           !S_ISDIR(path_stat.st_mode)) {
				log_error("module, invalid directory '%s'",
				          MODULE_DIR);
			ret = KNOT_EINVAL;
		} else {
			ret = glob(path, 0, NULL, &glob_buf);
			if (ret != 0 && ret != GLOB_NOMATCH) {
				log_error("module, failed to read directory '%s'",
				          MODULE_DIR);
				ret = KNOT_EACCES;
			} else {
				ret = KNOT_EOK;
			}
		}

		// Process each module in the directory.
		for (size_t i = 0; i < glob_buf.gl_pathc; i++) {
			ret = conf_mod_load_extra(conf, NULL, glob_buf.gl_pathv[i],
			                          false);
			if (ret != KNOT_EOK) {
				break;
			}
		}

		globfree(&glob_buf);
		free(path);
	}

	conf_mod_load_purge(conf, false);

	return ret;
}

int conf_mod_load_extra(
	conf_t *conf,
	const char *mod_name,
	const char *file_name,
	bool temporary)
{
	if (conf == NULL || (mod_name == NULL && file_name == NULL)) {
		return KNOT_EINVAL;
	}

	// Synthesize module file name if not specified.
	char *tmp_name = NULL;
	if (file_name == NULL) {
		tmp_name = sprintf_alloc("%s/%s%s", MODULE_INSTDIR,
		                         mod_name + strlen(KNOTD_MOD_NAME_PREFIX),
		                         LIB_EXTENSION);
		if (tmp_name == NULL) {
			return KNOT_ENOMEM;
		}
		file_name = tmp_name;
	}

	void *handle = dlopen(file_name, RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		log_error("module, failed to open '%s' (%s)", file_name, dlerror());
		free(tmp_name);
		return KNOT_ENOENT;
	}
	(void)dlerror();

	knotd_mod_api_t *api = dlsym(handle, "knotd_mod_api");
	if (api == NULL) {
		char *err = dlerror();
		if (err == NULL) {
			err = "empty symbol";
		}
		log_error("module, invalid library '%s' (%s)", file_name, err);
		dlclose(handle);
		free(tmp_name);
		return KNOT_ENOENT;
	}
	free(tmp_name);

	if (api->version != KNOTD_MOD_ABI_VERSION) {
		log_error("module '%s', incompatible version", api->name);
		dlclose(handle);
		return KNOT_ENOTSUP;
	}

	if (api->name == NULL || (mod_name != NULL && strcmp(api->name, mod_name) != 0)) {
		log_error("module '%s', module name mismatch", api->name);
		dlclose(handle);
		return KNOT_ENOTSUP;
	}

	// Check if the module is already loaded.
	module_t *found = conf_mod_find(conf, api->name, strlen(api->name), temporary);
	if (found != NULL) {
		log_error("module '%s', duplicate module", api->name);
		dlclose(handle);
		return KNOT_EEXIST;
	}

	module_t *mod = calloc(1, sizeof(*mod));
	if (mod == NULL) {
		dlclose(handle);
		return KNOT_ENOMEM;
	}
	mod->api = api;
	mod->lib_handle = handle;
	mod->temporary = temporary;

	int ret = mod_load(conf, mod);
	if (ret != KNOT_EOK) {
		log_error("module '%s', failed to load (%s)", api->name,
		          knot_strerror(ret));
		dlclose(handle);
		free(mod);
		return ret;
	}

	mod_dynarray_add(&conf->modules, &mod);

	log_debug("module '%s', loaded shared", api->name);

	return KNOT_EOK;
}

static void unload_shared(
	module_t *mod)
{
	if (mod != NULL) {
		assert(mod->lib_handle);
		(void)dlclose(mod->lib_handle);
		free(mod);
	}
}

void conf_mod_load_purge(
	conf_t *conf,
	bool temporary)
{
	if (conf == NULL) {
		return;
	}

	// Switch the current temporary schema with the initial one.
	if (temporary && conf->old_schemas.size > 0) {
		yp_item_t **current_schema = &conf->schema;
		yp_item_t **initial = &(conf->old_schemas.arr)[0];

		yp_item_t *old_schema = rcu_xchg_pointer(current_schema, *initial);
		synchronize_rcu();
		*initial = old_schema;
	}

	dynarray_foreach(old_schema, yp_item_t *, schema, conf->old_schemas) {
		yp_schema_free(*schema);
	}
	old_schema_dynarray_free(&conf->old_schemas);

	dynarray_foreach(mod, module_t *, module, conf->modules) {
		if ((*module) != NULL && (*module)->temporary) {
			unload_shared((*module));
			*module = NULL; // Cannot remove from dynarray.
		}
	}
}

void conf_mod_unload_shared(
	conf_t *conf)
{
	if (conf == NULL) {
		return;
	}

	dynarray_foreach(mod, module_t *, module, conf->modules) {
		unload_shared((*module));
	}
	mod_dynarray_free(&conf->modules);
}

#define LOG_ARGS(mod_id, msg) "module '%s%s%.*s', " msg, \
	mod_id->name + 1, (mod_id->len > 0) ? "/" : "", (int)mod_id->len, \
	mod_id->data

#define MOD_ID_LOG(zone, level, mod_id, msg, ...) \
	if (zone != NULL) \
		log_zone_##level(zone, LOG_ARGS(mod_id, msg), ##__VA_ARGS__); \
	else \
		log_##level(LOG_ARGS(mod_id, msg), ##__VA_ARGS__);

void conf_activate_modules(
	conf_t *conf,
	const knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan)
{
	int ret = KNOT_EOK;

	if (conf == NULL || query_modules == NULL || query_plan == NULL) {
		ret = KNOT_EINVAL;
		goto activate_error;
	}

	conf_val_t val;

	// Get list of associated modules.
	if (zone_name != NULL) {
		val = conf_zone_get(conf, C_MODULE, zone_name);
	} else {
		val = conf_default_get(conf, C_GLOBAL_MODULE);
	}

	switch (val.code) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT: // Check if a module is configured at all.
		return;
	default:
		ret = val.code;
		goto activate_error;
	}

	// Create query plan.
	*query_plan = query_plan_create(conf->mm);
	if (*query_plan == NULL) {
		ret = KNOT_ENOMEM;
		goto activate_error;
	}

	// Initialize query modules list.
	init_list(query_modules);

	// Open the modules.
	while (val.code == KNOT_EOK) {
		conf_mod_id_t *mod_id = conf_mod_id(&val);
		if (mod_id == NULL) {
			ret = KNOT_ENOMEM;
			goto activate_error;
		}

		// Open the module.
		knotd_mod_t *mod = query_module_open(conf, mod_id, *query_plan,
		                                     zone_name, conf->mm);
		if (mod == NULL) {
			MOD_ID_LOG(zone_name, error, mod_id, "failed to open");
			conf_free_mod_id(mod_id);
			goto skip_module;
		}

		// Check the module scope.
		if ((zone_name == NULL && !(mod->api->flags & KNOTD_MOD_FLAG_SCOPE_GLOBAL)) ||
		    (zone_name != NULL && !(mod->api->flags & KNOTD_MOD_FLAG_SCOPE_ZONE))) {
			MOD_ID_LOG(zone_name, error, mod_id, "out of scope");
			query_module_close(mod);
			goto skip_module;
		}

		// Check if the module is loadable.
		if (mod->api->load == NULL) {
			MOD_ID_LOG(zone_name, debug, mod_id, "empty module, not loaded");
			query_module_close(mod);
			goto skip_module;
		}

		// Load the module.
		ret = mod->api->load(mod);
		if (ret != KNOT_EOK) {
			MOD_ID_LOG(zone_name, error, mod_id, "failed to load (%s)",
			        knot_strerror(ret));
			query_module_close(mod);
			goto skip_module;
		}
		mod->config = NULL; // Invalidate the current config.

		add_tail(query_modules, &mod->node);
skip_module:
		conf_val_next(&val);
	}

	return;
activate_error:
	CONF_LOG(LOG_ERR, "failed to activate modules (%s)", knot_strerror(ret));
}

void conf_deactivate_modules(
	list_t *query_modules,
	struct query_plan **query_plan)
{
	if (query_modules == NULL || query_plan == NULL) {
		return;
	}

	// Free query plan.
	query_plan_free(*query_plan);
	*query_plan = NULL;

	// Free query modules list.
	knotd_mod_t *mod = NULL, *next = NULL;
	WALK_LIST_DELSAFE(mod, next, *query_modules) {
		if (mod->api->unload != NULL) {
			mod->api->unload(mod);
		}
		query_module_close(mod);
	}
	init_list(query_modules);
}
