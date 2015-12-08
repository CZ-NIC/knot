/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "error.h"
#include "fs.h"
#include "kasp/dir/file.h"
#include "kasp/dir/policy.h"
#include "kasp/dir/zone.h"
#include "kasp/internal.h"
#include "kasp/zone.h"
#include "key.h"
#include "list.h"
#include "path.h"
#include "shared.h"

#define KASP_DIR_INIT_MODE (S_IRWXU|S_IRGRP|S_IXGRP)

typedef struct kasp_dir_ctx {
	char *path;
} kasp_dir_ctx_t;

static int file_exists(const char *path)
{
	if (access(path, F_OK) == 0) {
		return DNSSEC_EOK;
	} else if (errno == ENOENT) {
		return DNSSEC_NOT_FOUND;
	} else {
		return dnssec_errno_to_error(errno);
	}
}

/* -- generic entity encoding ---------------------------------------------- */

static int entity_remove(const char *entity, void *_ctx, const char *name)
{
	assert(entity);
	assert(_ctx);
	assert(name);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_free_ char *config = file_from_entity(ctx->path, entity, name);
	if (!config) {
		return DNSSEC_ENOMEM;
	}

	if (unlink(config) != 0) {
		return dnssec_errno_to_error(errno);
	}

	return DNSSEC_EOK;
}

static int entity_exists(const char *entity, void *_ctx, const char *name)
{
	assert(entity);
	assert(_ctx);
	assert(name);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_free_ char *config = file_from_entity(ctx->path, entity, name);
	if (!config) {
		return DNSSEC_ENOMEM;
	}

	return file_exists(config);
}

static int entity_list(const char *entity, void *_ctx, dnssec_list_t *names)
{
	assert(entity);
	assert(_ctx);
	assert(names);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_closedir_ DIR *dir = opendir(ctx->path);
	if (!dir) {
		return DNSSEC_NOT_FOUND;
	}

	int error;
	struct dirent entry, *result;
	while (error = readdir_r(dir, &entry, &result), error == 0 && result) {
		char *zone = file_to_entity(entity, entry.d_name);
		if (zone) {
			dnssec_list_append(names, zone);
		}
	}

	if (error != 0) {
		return dnssec_errno_to_error(error);
	}

	return DNSSEC_EOK;
}

#define entity_io(entity, ctx, object, callback) \
({ \
	const char *path = ((kasp_dir_ctx_t *)ctx)->path; \
	const char *name = object->name; \
	_cleanup_free_ char *config = file_from_entity(entity, path, name); \
	config ? callback(object, config) : DNSSEC_ENOMEM; \
})

/* -- internal API --------------------------------------------------------- */

static int kasp_dir_init(const char *config)
{
	assert(config);

	// TODO: maybe check if the directory is empty?

	return fs_mkdir(config, KASP_DIR_INIT_MODE, true);
}

static int kasp_dir_open(void **ctx_ptr, const char *config)
{
	assert(ctx_ptr);
	assert(config);

	kasp_dir_ctx_t *ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(ctx);
	ctx->path = path_normalize(config);
	if (!ctx->path) {
		free(ctx);
		return DNSSEC_NOT_FOUND;
	}

	*ctx_ptr = ctx;
	return DNSSEC_EOK;
}

static void kasp_dir_close(void *_ctx)
{
	assert(_ctx);

	kasp_dir_ctx_t *ctx = _ctx;

	free(ctx->path);
	free(ctx);
}

/* -- entities ------------------------------------------------------------- */

#define ENTITY_ZONE     "zone"

static int kasp_dir_zone_remove(void *ctx, const char *name)
{
	return entity_remove(ENTITY_ZONE, ctx, name);
}

static int kasp_dir_zone_exists(void *ctx, const char *name)
{
	return entity_exists(ENTITY_ZONE, ctx, name);
}

static int kasp_dir_zone_list(void *ctx, dnssec_list_t *names)
{
	return entity_list(ENTITY_ZONE, ctx, names);
}

static int kasp_dir_zone_load(void *ctx, dnssec_kasp_zone_t *zone)
{
	return entity_io(ENTITY_ZONE, ctx, zone, load_zone_config);
}

static int kasp_dir_zone_save(void *ctx, dnssec_kasp_zone_t *zone)
{
	return entity_io(ENTITY_ZONE, ctx, zone, save_zone_config);
}

#define ENTITY_POLICY   "policy"

static int kasp_dir_policy_remove(void *ctx, const char *name)
{
	return entity_remove(ENTITY_POLICY, ctx, name);
}

static int kasp_dir_policy_exists(void *ctx, const char *name)
{
	return entity_exists(ENTITY_POLICY, ctx, name);
}

static int kasp_dir_policy_list(void *ctx, dnssec_list_t *names)
{
	return entity_list(ENTITY_POLICY, ctx, names);
}

static int kasp_dir_policy_load(void *ctx, dnssec_kasp_policy_t *policy)
{
	return entity_io(ENTITY_POLICY, ctx, policy, load_policy_config);
}

static int kasp_dir_policy_save(void *ctx, dnssec_kasp_policy_t *policy)
{
	return entity_io(ENTITY_POLICY, ctx, policy, save_policy_config);
}

#define ENTITY_KEYSTORE "keystore"

static int kasp_dir_keystore_remove(void *ctx, const char *name)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int kasp_dir_keystore_exists(void *ctx, const char *name)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int kasp_dir_keystore_list(void *ctx, dnssec_list_t *names)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int kasp_dir_keystore_load(void *ctx, dnssec_kasp_keystore_t *keystore)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int kasp_dir_keystore_save(void *ctx, dnssec_kasp_keystore_t *keystore)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

#define ENTITY_CALLBACKS(name) \
  .name##_load   = kasp_dir_##name##_load,   \
  .name##_save   = kasp_dir_##name##_save,   \
  .name##_remove = kasp_dir_##name##_remove, \
  .name##_list   = kasp_dir_##name##_list,   \
  .name##_exists = kasp_dir_##name##_exists

static const dnssec_kasp_store_functions_t KASP_DIR_FUNCTIONS = {
	.init  = kasp_dir_init,
	.open  = kasp_dir_open,
	.close = kasp_dir_close,
	ENTITY_CALLBACKS(zone),
	ENTITY_CALLBACKS(policy),
	ENTITY_CALLBACKS(keystore),
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_init_dir(dnssec_kasp_t **kasp_ptr)
{
	return dnssec_kasp_create(kasp_ptr, &KASP_DIR_FUNCTIONS);
}
