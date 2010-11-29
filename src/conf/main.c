#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "conf.h"

static int conf_fd;
static char *config_name = "cutedns.conf";

static int cf_read(unsigned char *dest, unsigned int len)
{
	int l = read(conf_fd, dest, len);
	if (l < 0) {
		cf_error("Read error");
	}
	return l;
}

int main(int argc, void **argv)
{
	int ret;
	char *name = config_name;
	struct config *conf = config_alloc(name);

	conf_fd = open(name, O_RDONLY);
	if (conf_fd < 0) {
		return 1;
	}
	cf_read_hook = cf_read;
	ret = config_parse(conf);
	close(conf_fd);
	return ret;
}
