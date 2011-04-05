/*!
 * \file hash-functions.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Various hash functions.
 *
 * All of the hash functions are downloaded from various sources.
 *
 * \todo Add references to sources.
 *
 * \addtogroup hashing
 * @{
 */

#ifndef _KNOT_HASH_FUNCTIONS_H_
#define _KNOT_HASH_FUNCTIONS_H_

typedef  unsigned long int  u4;   /* unsigned 4-byte type */
typedef  unsigned     char  u1;   /* unsigned 1-byte type */

/*!
 * \brief Fowler/Noll/Vo Hash.
 *
 * Downloaded from ???
 *
 * \param data Data to hash.
 * \param size Size of the data in bytes.
 * \param bits
 *
 * \return Hash of the data.
 *
 * \todo Add source.
 */
unsigned long int fnv_hash(const char *data, int size, int bits);

//unsigned long int fnv_hash2(char *data, int size, int bits);

/*!
 * \brief Jenkins hash function.
 *
 * Downloaded from ???
 *
 * \param k Data to hash
 * \param length Size of the data in bytes.
 * \param initval The previous hash or an arbitrary value.
 *
 * \return Hash of the data.
 *
 * \todo Add source.
 */
u4 jhash(register u1 *k, u4 length, u4 initval);

/*!
 * \brief SDBM hash function.
 *
 * Downloaded from ??? (a very similar version is here:
 * http://www.partow.net/programming/hashfunctions/).
 *
 * \param key Key to hash.
 * \param size Size of the key in bytes.
 *
 * \return Hash of the data.
 *
 * \todo Add source.
 */
unsigned long sdbm_hash(const unsigned char *key, int size);

/*!
 * \brief DJB Hash (by Daniel J. Bernstein).
 *
 * Downloaded from ???
 *
 * \param key Key to hash.
 * \param size Size of the key in bytes.
 *
 * \return Hash of the data.
 *
 * \todo Add source.
 */
unsigned long djb_hash(const unsigned char *key, int size);

//unsigned long jsw_hash( const unsigned char *key, int size );

/*!
 * \brief ELF hash function.
 *
 * Downloaded from ???
 *
 * \param key Key to hash.
 * \param size Size of the key in bytes.
 *
 * \return Hash of the data.
 *
 * \todo Add source.
 */
unsigned long elf_hash(const unsigned char *key, int size);

#endif /* _KNOT_HASH_FUNCTIONS_H_ */

/*! @} */
