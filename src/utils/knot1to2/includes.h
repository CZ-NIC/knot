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

#pragma once

#include <stdbool.h>
#include <stdio.h>

/*!
 * \brief Structure to hold data for one include in configuration file.
 */
typedef struct {
	char *filename;
	FILE *handle;
} conf_include_t;

/*!
 * \brief Structure to keep config file includes stack.
 */
struct conf_includes;
typedef struct conf_includes conf_includes_t;

/*!
 * \brief Initialize structure for storing names of included files.
 */
conf_includes_t *conf_includes_init(void);

/*!
 * \brief Free structure for storing the names of included files.
 */
void conf_includes_free(conf_includes_t *includes);

/**
 * \brief Pushes a file name onto the stack of files.
 *
 * If the file name is not absolute (or first inserted), the name is changed
 * to be relative to previously inserted file name.
 *
 * \param filename  File name to be stored (and processed). It is copied.
 *
 * \return Success.
 */
bool conf_includes_push(conf_includes_t *includes, const char *filename);

/**
 * \brief Returns an include on the top of the stack.
 *
 * \return File name on the top of the stack. Do not free it.
 */
conf_include_t *conf_includes_top(conf_includes_t *includes);

/**
 * \brief Returns an include on the top of the stack and removes it.
 *
 * \return File name on the top of the stack. Caller should free the result.
 */
conf_include_t *conf_includes_pop(conf_includes_t *includes);

/**
 * \brief Remove the include on the top.
 *
 * \return True if the include was removed.
 */
bool conf_includes_remove(conf_includes_t *includes);
