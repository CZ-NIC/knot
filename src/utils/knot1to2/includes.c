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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/knot1to2/includes.h"

#define INCLUDES_CAPACITY_BLOCK 128 	// Size of included files block.

/*!
 * \brief Structure to store names of files included into the config.
 */
struct conf_includes {
	int free_index;			//!< First free index in 'names'.
	int capacity;			//!< Maximal capacity.
	conf_include_t *files;		//!< Stored includes.
};

/*!
 * \brief Initialize structure for storing names of included files.
 */
conf_includes_t *conf_includes_init(void)
{
	conf_includes_t *includes = calloc(1, sizeof(conf_includes_t));
	if (!includes) {
		return NULL;
	}

	conf_include_t *files = calloc(INCLUDES_CAPACITY_BLOCK,
	                               sizeof(conf_include_t));
	if (!files) {
		free(includes);
		return NULL;
	}

	includes->capacity = INCLUDES_CAPACITY_BLOCK;
	includes->files = files;

	return includes;
}

/*!
 * \brief Free structure for storing the names of included files.
 */
void conf_includes_free(conf_includes_t *includes)
{
	if (!includes) {
		return;
	}

	while (conf_includes_remove(includes));

	free(includes->files);
	free(includes);
}

/**
 * \brief Constructs a path relative to a reference file.
 *
 * e.g. path_relative_to("b.conf", "samples/a.conf") == "samples/b.conf"
 *
 * \param filename   File name of the target file.
 * \param reference  Reference file name (just path is used).
 *
 * \return Relative path to a reference file.
 */
static char *path_relative_to(const char *filename, const char *reference)
{
	char *path_end = strrchr(reference, '/');
	if (!path_end) {
		return strdup(filename);
	}

	int path_len = (int)(path_end - reference);
	size_t result_len = path_len + 1 + strlen(filename) + 1;
	char *result = malloc(result_len * sizeof(char));
	if (!result) {
		return NULL;
	}

	int ret = snprintf(result, result_len, "%.*s/%s", path_len, reference, filename);
	if (ret < 0 || ret >= result_len) {
		free(result);
		return NULL;
	}

	return result;
}

/**
 * \brief Pushes a file name onto the stack of files.
 */
bool conf_includes_push(conf_includes_t *includes, const char *filename)
{
	if (!includes || !filename) {
		return false;
	}

	char *store = NULL;

	if (includes->free_index == 0 || filename[0] == '/') {
		store = strdup(filename);
	} else {
		conf_include_t *previous = &includes->files[includes->free_index - 1];
		store = path_relative_to(filename, previous->filename);
	}

	for (int i = 0; i < includes->free_index; i++) {
		// Check for include loop.
		if (strcmp(includes->files[i].filename, store) == 0) {
			free(store);
			return false;
		}
	}

	// Extend the stack if full.
	if (includes->free_index >= includes->capacity) {
		size_t new_size = (includes->capacity + INCLUDES_CAPACITY_BLOCK) *
	                          sizeof(conf_include_t);
		conf_include_t *new_files = realloc(includes->files, new_size);
		if (new_files == NULL) {
			free(store);
			return false;
		}
		includes->capacity = new_size;
		includes->files = new_files;
	}

	conf_include_t new_include = {
		.filename = store,
		.handle = NULL
	};

	includes->files[includes->free_index++] = new_include;

	return store != NULL;
}

/**
 * \brief Returns an include on the top of the stack.
 */
conf_include_t *conf_includes_top(conf_includes_t *includes)
{
	if (!includes || includes->free_index == 0) {
		return NULL;
	}

	return includes->files + includes->free_index - 1;
}

/**
 * \brief Returns an include on the top of the stack and removes it.
 */
conf_include_t *conf_includes_pop(conf_includes_t *includes)
{
	conf_include_t *result = conf_includes_top(includes);
	if (result) {
		includes->free_index -= 1;
	}

	return result;
}

/**
 * \brief Returns an include on the top of the stack and removes it.
 */
bool conf_includes_remove(conf_includes_t *includes)
{
	conf_include_t *top = conf_includes_pop(includes);
	if (top) {
		if (top->filename) {
			free(top->filename);
			top->filename = NULL;
		}
		if (top->handle) {
			fclose(top->handle);
			top->handle = NULL;
		}

		return true;
	}

	return false;
}
