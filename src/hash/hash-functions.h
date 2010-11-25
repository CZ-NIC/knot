#ifndef HASH_FUNCTIONS
#define HASH_FUNCTIONS

typedef  unsigned long int  u4;   /* unsigned 4-byte type */
typedef  unsigned     char  u1;   /* unsigned 1-byte type */

unsigned long int fnv_hash(const char *data, int size, int bits);

unsigned long int fnv_hash2(char *data, int size, int bits);

u4 jhash(register u1 *k, u4 length, u4 initval);

unsigned long sdbm_hash(const unsigned char *key, int size);

unsigned long djb_hash(const unsigned char *key, int size);

//unsigned long jsw_hash( const unsigned char *key, int size );

unsigned long elf_hash(const unsigned char *key, int size);

#endif
