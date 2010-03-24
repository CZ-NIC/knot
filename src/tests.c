#include "tests.h"
#include "bitset.h"
#include "common.h"

#include <stdlib.h>
#include <stdio.h>
/*----------------------------------------------------------------------------*/

int test_bitset()
{
    bitset_t bitset;
    uint n = 1048576, i, c, err = 0;
    uint *numbers = malloc(n/2 * sizeof(uint));

    BITSET_CREATE(&bitset, n);
    BITSET_CLEAR(bitset, n);

    printf("New bitset created.\n");

    // check if empty
    for (i = 0; i < n; i++) {
        if (BITSET_GET(bitset, i) != 0) {
            printf("Bit %u not clear!\n", i);
            err++;
        }
    }

    srand(1);

    printf("Setting random bits...\n");

    // set random bits, but keep track of them
    for (i = 0; i < n/2; i++) {
        c = rand() % n;
        //printf("Setting bit on position %u..\n", c);
        numbers[i] = c;
        BITSET_SET(bitset, c);

        if (!BITSET_ISSET(bitset, c)) {
            printf("Bit %u not set successfully!\n", c);
            err++;
        }

        BITSET_UNSET(bitset, c);
    }

    printf("Testing borders...\n");
    // setting bits on the borders
    BITSET_SET(bitset, 0);
    if (!BITSET_ISSET(bitset, 0)) {
        printf("Error setting bit on position 0.\n");
        err++;
    }
    BITSET_UNSET(bitset, 0);

    BITSET_SET(bitset, 31);
    if (!BITSET_ISSET(bitset, 31)) {
        printf("Error setting bit on position 31.\n");
        err++;
    }
    BITSET_UNSET(bitset, 31);

    BITSET_SET(bitset, 32);
    if (!BITSET_ISSET(bitset, 32)) {
        printf("Error setting bit on position 32.\n");
        err++;
    }
    BITSET_UNSET(bitset, 32);

    BITSET_SET(bitset, 33);
    if (!BITSET_ISSET(bitset, 33)) {
        printf("Error setting bit on position 33.\n");
        err++;
    }
    BITSET_UNSET(bitset, 33);

    BITSET_SET(bitset, 1048575);
    if (!BITSET_ISSET(bitset, 1048575)) {
        printf("Error setting bit on position 1048575.\n");
        err++;
    }
    BITSET_UNSET(bitset, 1048575);

    // check if empty
    for (i = 0; i < n; i++) {
        if (BITSET_GET(bitset, i) != 0) {
            printf("Bit %u not clear!\n", i);
            err++;
        }
    }

    free(numbers);
    BITSET_DESTROY(&bitset);

    printf("There were %u errors.\n", err);
    return 0;
}
