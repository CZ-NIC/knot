/*!
 * \file log.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Logging facility (configuration file interface).
 *
 * \addtogroup logging
 * @{
 */
#ifndef _CUTEDNS_LOGCONF_H_
#define _CUTEDNS_LOGCONF_H_

struct conf_t;

/*!
 * \brief Setup logging facilities from config.
 *
 * \todo There might be some issues with reloading config
 *       on-the-fly in multithreaded environment, check afterwards.
 *
 * \see syslog.h
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int log_conf_hook(const struct conf_t *conf);

#endif /* _CUTEDNS_LOGCONF_H_ */

/*! @} */
