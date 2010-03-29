#include "print.h"
#include <stdio.h>

/*----------------------------------------------------------------------------*/
/* Downloaded from http://www.digitalpeer.com/id/print                        */
/*----------------------------------------------------------------------------*/
void hex_print( const char *data, int length )
{
    int ptr = 0;
    for(;ptr < length;ptr++)
    {
        printf("0x%02x ",(unsigned char)*(data+ptr));
    }
    printf("\n");
}

/*----------------------------------------------------------------------------*/
/* Downloaded from http://www.digitalpeer.com/id/print                        */
/*----------------------------------------------------------------------------*/
void bit_print( const char *data, int length )
{
    unsigned char mask = 0x01;
    int ptr = 0;
    int bit = 0;
    for(;ptr < length;ptr++)
    {
        for(bit = 7;bit >= 0;bit--)
        {
            if ((mask << bit) & (unsigned char)*(data+ptr))
            {
                printf("1");
            }
            else
            {
                printf("0");
            }
        }
        printf(" ");
    }
    printf("\n");
}
