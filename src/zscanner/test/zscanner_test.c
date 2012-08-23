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
#include "zscanner/test/processing.h"
#include "zscanner/test/tests.h"

/*! \brief Print help. */
void help(int argc, char **argv)
{
    printf("\nZone scanner testing tool.\n"
           "Usage: %s [parameters] origin zonefile\n", argv[0]);
    printf("Parameters:\n"
           " -e           Empty processing.\n"
           " -t           Launch unit tests.\n"
           " -h           Print this help.\n");
}

int main(int argc, char *argv[])
{
    // Parsed command line arguments.
    int c = 0, li = 0;
    int ret, empty = 0, test = 0;
    file_loader_t *fl;
    const char *origin;
    const char *zone_file;

    // Command line long options.
    struct option opts[] = {
        {"empty",       no_argument,       0, 'e'},
        {"test",        no_argument,       0, 't'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // Command line options processing.
    while ((c = getopt_long(argc, argv, "eth", opts, &li)) != -1) {
        switch (c) {
        case 'e':
            empty = 1;
            break;
        case 't':
            test = 1;
            break;
        case 'h': // Fall through.
        default:
            help(argc, argv);
            return EXIT_FAILURE;
        }
    }

    if (test == 1) {
        test__date_to_timestamp();
    }
    else {
        // Check if there are 2 remaining non-options.
        if (argc - optind != 2) {
            help(argc, argv);
            return EXIT_FAILURE;
        }

        zone_file = argv[optind];
        origin = argv[optind + 1];

        if (empty == 1) {
            void empty_process_record(const scanner_t *s) { };
            void empty_process_error(const scanner_t *s) { };

            fl = file_loader_create(origin,
                                    zone_file,
                                    DEFAULT_CLASS,
                                    DEFAULT_TTL,
                                    &empty_process_record,
                                    &empty_process_error);
        }
        else {
            fl = file_loader_create(origin,
                                    zone_file,
                                    DEFAULT_CLASS,
                                    DEFAULT_TTL,
                                    &process_record,
                                    &process_error);
        }

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
    }

    return EXIT_SUCCESS;
}

