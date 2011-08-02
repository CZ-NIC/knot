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

#ifndef _KNOTDLOGCONF_H_
#define _KNOTDLOGCONF_H_

struct conf_t;

/*!
 * \brief Setup logging facilities from config.
 *
 * \see syslog.h
 *
 * \retval KNOTDEOK on success.
 * \retval KNOTDEINVAL on invalid parameters.
 * \retval KNOTDENOMEM out of memory error.
 */
int log_conf_hook(const struct conf_t *conf, void *data);

#endif /* _KNOTDLOGCONF_H_ */

/*! @} */
