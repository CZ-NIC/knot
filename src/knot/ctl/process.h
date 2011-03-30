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
 * \retval PID on success.
 * \retval negative integer on error (EINVAL, ENOENT, ERANGE).
 */
pid_t pid_read(const char* fn);

/*!
 * \brief Write PID to given file.
 *
 * \param fn Filename containing PID.
 *
 * \retval 0 on success (EOK).
 * \retval negative integer on error (ENOENT, EINVAL, ERROR).
 */
int pid_write(const char* fn);

/*!
 * \brief Remove file containing PID.
 *
 * \param fn Filename containing PID.
 *
 * \warning Filename content won't be checked.
 *
 * \retval 0 on success (EOK).
 * \retval negative integer on error (EINVAL).
 */
int pid_remove(const char* fn);

/*!
 * \brief Return true if the PID is running.
 *
 * \param pid Process ID.
 *
 * \retval True if running.
 * \retval False if not running or on errors.
 */
int pid_running(pid_t pid);

#endif // _KNOT_PROCESS_H_
