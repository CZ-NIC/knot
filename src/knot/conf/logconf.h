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
#ifndef _KNOT_LOGCONF_H_
#define _KNOT_LOGCONF_H_

struct conf_t;

/*!
 * \brief Setup logging facilities from config.
 *
 * \see syslog.h
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int log_conf_hook(const struct conf_t *conf, void *data);

#endif /* _KNOT_LOGCONF_H_ */

/*! @} */
