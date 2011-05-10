/*!
 * \file sockaddr.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Socket address abstraction layer.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOT_SOCKADDR_H_
#define _KNOT_SOCKADDR_H_

#include <netinet/in.h>

/*! \brief Universal socket address. */
typedef struct sockaddr_t {
	int family; /*!< Address family. */
	struct sockaddr* ptr; /*!< Pointer to used sockaddr. */
	socklen_t len;              /*!< Length of used sockaddr. */
	union {
		struct sockaddr_in addr4; /*!< IPv4 sockaddr. */
#ifndef DISABLE_IPV6
		struct sockaddr_in6 addr6; /*!< IPv6 sockaddr. */
#endif
	};
} sockaddr_t;

/*!
 * \brief Initialize address structure.
 *
 * Members ptr and len will be initialized to correct address family.
 *
 * \param addr Socket address structure
 * \param af Requested address family.
 *
 * \retval 0 on success.
 * \retval -1 on unsupported address family (probably INET6).
 */
int sockaddr_init(sockaddr_t *addr, int af);

/*!
 * \brief Update internal pointers according to length.
 *
 * \param addr Socket address structure
 *
 * \retval 0 on success.
 * \retval -1 on invalid size.
 */
int sockaddr_update(sockaddr_t *addr);

/*! \brief Set address and port.
 *
 * \brief dst Target address structure.
 * \brief family Address family.
 * \brief addr IP address in string format.
 * \brief port Port.
 *
 * \retval 0 if addr is not valid address in string format.
 * \retval positive value in case of success.
 * \retval -1 on error.
 * \see inet_pton(3)
 */
int sockaddr_set(sockaddr_t *dst, int family, const char* addr, int port);

#endif /* _KNOT_SOCKADDR_H_ */

/*! @} */
