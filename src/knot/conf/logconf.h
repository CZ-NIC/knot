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

#ifndef _KNOTD_LOGCONF_H_
#define _KNOTD_LOGCONF_H_

struct conf_t;

/*!
 * \brief Setup logging facilities from config.
 *
 * \see syslog.h
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL on invalid parameters.
 * \retval KNOTD_ENOMEM out of memory error.
 */
int log_conf_hook(const struct conf_t *conf, void *data);

#endif /* _KNOTD_LOGCONF_H_ */

/*! @} */
