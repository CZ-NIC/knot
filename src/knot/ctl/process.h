/*!
 * \file process.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Functions for POSIX process handling.
 *
 * \addtogroup ctl
 * @{
 */

#ifndef _KNOT_PROCESS_H_
#define _KNOT_PROCESS_H_

#include <unistd.h>

/*!
 * \brief Return a filename of the default compiled database file.
 *
 * \retval Filename of the database file.
 * \retval NULL if not exists.
 */
char* pid_filename();

/*!
 * \brief Read PID from given file.
 *
 * \param fn Filename containing PID.
 *
 * \retval PID on success (positive integer).
 * \retval KNOT_EINVAL on null path.
 * \retval KNOT_ENOENT if the filename content cannot be read.
 * \retval KNOT_ERANGE if the stored PID is out of range.
 */
pid_t pid_read(const char* fn);

/*!
 * \brief Write PID to given file.
 *
 * \param fn Filename containing PID.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on null path.
 * \retval KNOT_ENOENT filename cannot be opened for writing.
 * \retval KNOT_ERROR unspecified error.
 */
int pid_write(const char* fn);

/*!
 * \brief Remove file containing PID.
 *
 * \param fn Filename containing PID.
 *
 * \warning Filename content won't be checked.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL failed to remove filename.
 */
int pid_remove(const char* fn);

/*!
 * \brief Return true if the PID is running.
 *
 * \param pid Process ID.
 *
 * \retval 1 if running.
 * \retval 0 if not running (or error).
 */
int pid_running(pid_t pid);

#endif // _KNOT_PROCESS_H_

/*! @} */
