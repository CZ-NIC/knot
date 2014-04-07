#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "path.h"

char *path_normalize(const char *path)
{
	char real[MAX_PATH] = { '\0' };
	if (!realpath(path, real)) {
		return NULL;
	};

	struct stat st = { 0 };
	if (stat(real, &st) == -1) {
		return NULL;
	}

	if (!S_ISDIR(st.st_mode)) {
		return NULL;
	}

	return strdup(real);
}
