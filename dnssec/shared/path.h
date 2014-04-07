#pragma once

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

/*!
 * Normalize path to a file or a directory.
 */
char *path_normalize(const char *path);
