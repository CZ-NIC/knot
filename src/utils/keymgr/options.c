/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sys/stat.h>
#include <unistd.h>

#include <dnssec/error.h>
#include "knot/conf/conf.h"
#include "knot/dnssec/context.h"
#include "options.h"
#include "shared/print.h"

/*!
 * Initialize kasp_dir in legacy mode.
 */
static int options_init_legacy(options_t *options)
{
	assert(options);

	if (options->kasp_dir) {
		return DNSSEC_EOK;
	}

	char *env = getenv("KEYMGR_DIR");
	if (env) {
		options->kasp_dir = strdup(env);
		return options->kasp_dir ? DNSSEC_EOK : DNSSEC_ENOMEM;
	}

	options->kasp_dir = getcwd(NULL, 0);
	return options->kasp_dir ? DNSSEC_EOK : DNSSEC_ENOMEM;
}

/*!
 * Initialize kasp_dir with policies in database.
 */
static int options_init_modern(options_t *options)
{
	assert(options);

	if (options->config != NULL && options->confdb != NULL) {
		error("Ambiguous configuration source.");
		return DNSSEC_EINVAL;
	}

	// Choose the optimal config source.
	struct stat st;
	bool import = false;
	if (options->kasp_dir != NULL) {
		import = false;
	} else if (options->confdb != NULL) {
		import = false;
	} else if (options->config != NULL) {
		import = true;
	} else if (stat(CONF_DEFAULT_DBDIR, &st) == 0) {
		import = false;
		options->confdb = CONF_DEFAULT_DBDIR;
	} else if (stat(CONF_DEFAULT_FILE, &st) == 0) {
		import = true;
		options->config = CONF_DEFAULT_FILE;
	} else {
		error("Couldn't determine configuration source.");
		return DNSSEC_EINVAL;
	}

	// Prepare config flags.
	conf_flag_t flags = CONF_FNOHOSTNAME;
	if (options->confdb != NULL) {
		flags |= CONF_FREADONLY;
	}

	// Open confdb.
	conf_t *new_conf = NULL;
	if (conf_new(&new_conf, conf_scheme, options->confdb, flags) != KNOT_EOK) {
		error("Failed to open configuration database '%s'.",
		      (options->confdb != NULL) ? options->confdb : "");
		return DNSSEC_EINVAL;
	}

	// Import the config file.
	if (import) {
		if (conf_import(new_conf, options->config, true) != KNOT_EOK) {
			error("Failed to open configuration file '%s'.",
			      options->config);
			conf_free(new_conf);
			return DNSSEC_EINVAL;
		}
	}

	// Update to the new config.
	conf_update(new_conf, CONF_UPD_FNONE);

	return DNSSEC_EOK;
}

int options_init(options_t *options)
{
	if (options == NULL) {
		return DNSSEC_EINVAL;
	}

	if (options->legacy) {
		return options_init_legacy(options);
	} else {
		return options_init_modern(options);
	}
}

void options_cleanup(options_t *options)
{
	if (options == NULL) {
		return;
	}

	if (!options->legacy) {
		conf_update(NULL, CONF_UPD_FNONE);
	}

	free(options->kasp_dir);
}

int options_zone_kasp_path(options_t *options, const char *zone_name)
{
	if (options == NULL) {
		return DNSSEC_EINVAL;
	}

	if (options->kasp_dir != NULL) {
		return DNSSEC_EOK;
	}

	if (options->legacy || zone_name == NULL) {
		return DNSSEC_EINVAL;
	}

	uint8_t buff[KNOT_DNAME_MAXLEN];

	knot_dname_t *zone = knot_dname_from_str(buff, zone_name, sizeof(buff));
	if (zone == NULL || knot_dname_to_lower(zone) != KNOT_EOK) {
		error("Invalid zone name.");
		return DNSSEC_EINVAL;
	}

	// Check if such a zone is configured.
	if (!conf_rawid_exists(conf(), C_ZONE, zone, knot_dname_size(zone))) {
		error("Zone not configured.");
		return DNSSEC_EINVAL;
	}

	conf_val_t val = conf_zone_get(conf(), C_STORAGE, zone);
	char *storage = conf_abs_path(&val, NULL);
	val = conf_zone_get(conf(), C_KASP_DB, zone);
	options->kasp_dir = conf_abs_path(&val, storage);
	free(storage);
	if (options->kasp_dir == NULL) {
		return DNSSEC_EINVAL;
	}

	return DNSSEC_EOK;
}

int options_zone_kasp_init(options_t *options, const char *zone_name,
                           dnssec_kasp_t **kasp)
{
	if (options == NULL) {
		return DNSSEC_EINVAL;
	}

	if (options->legacy) {
		dnssec_kasp_init_dir(kasp);
		return DNSSEC_EOK;
	}

	if (zone_name == NULL || kasp == NULL) {
		return DNSSEC_EINVAL;
	}

	kdnssec_ctx_t ctx = {
		.legacy = options->legacy
	};

	int ret = kdnssec_kasp_init(&ctx, options->kasp_dir, zone_name);
	kdnssec_ctx_deinit(&ctx);
	if (ret != DNSSEC_EOK) {
		error("Failed to initialize KASP directory '%s'.", options->kasp_dir);
		return ret;
	}

	return kdnssec_kasp(kasp, options->legacy);
}
