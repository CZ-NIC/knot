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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <config.h>
#include <getopt.h>

#include "zscanner/file_loader.h"
#include "zscanner/test/test_functions.h"

/*! \brief Print help. */
void help(int argc, char **argv)
{
    printf("Usage: %s [parameters] origin zonefile\n",
           argv[0]);
    printf("Parameters:\n"
           " -V           Print version.\n"
           " -h           Print this help.\n");
}

int main(int argc, char *argv[])
{
    // Parsed command line arguments.
    int c = 0, li = 0;
    int ret;

    // Command line long options.
    struct option opts[] = {
        {"version",     no_argument,       0, 'V'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // Command line options processing.
    while ((c = getopt_long(argc, argv, "Vh", opts, &li)) != -1) {
        switch (c) {
        case 'V':
            printf("Zone compiler (Knot DNS %s)\n", PACKAGE_VERSION);
            return EXIT_SUCCESS;
        case 'h': // Fall through.
        default:
            help(argc, argv);
            return EXIT_FAILURE;
        }
    }

    // Check if there are 2 remaining non-options.
    if (argc - optind != 2) {
        help(argc, argv);
        return EXIT_FAILURE;
    }

    file_loader_t *fl;

    fl = file_loader_create(argv[2],
                            argv[1],
                            DEFAULT_CLASS,
                            DEFAULT_TTL,
                            &process_record,
                            &process_error);

    if (fl != NULL) {
        ret = file_loader_process(fl);
        file_loader_free(fl);

        if (ret != 0) {
            return EXIT_FAILURE;
        }
    }
    else {
        printf("File open error!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

