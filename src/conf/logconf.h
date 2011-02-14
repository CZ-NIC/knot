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

/*!
 * \brief Setup logging facilities from config.
 *
 * \see syslog.h
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int log_load_conf();

#endif /* _CUTEDNS_LOGCONF_H_ */

/*! @} */
