#include <stdio.h>

#include "common.h"
#include "cuckoo-test.h"

/*----------------------------------------------------------------------------*/

int main( int argc, char **argv )
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>.\n", argv[0]);
        return -1;
    }

    test_hash_table(argv[1]);

    //start_server(argv[1]);

    return 0;
}
