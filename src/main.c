#include <stdio.h>

#include "common.h"
#include "server.h"

/*----------------------------------------------------------------------------*/

int main( int argc, char **argv )
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>.\n", argv[0]);
        return -1;
    }

    cute_server *server = cute_create();
    return cute_start(server, argv[1]);
}
