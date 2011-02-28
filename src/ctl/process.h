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

/* Constants. */
enum {
	PID_NOFILE = -1, /* Cannot open file. */
	PID_EMPTY  = -2, /* File is empty. */
	PID_INVAL  = -3  /* Invalid conversion to/from string. */
};

/* PID handling */

/*!
 * \brief Return a filename of the default compiled database file.
 *
 * \retval Filename of the database file.
 * \retval NULL if not exists.
 *
 * \todo Implement properly using configuration file.
 */
char* pid_filename();

/*!
 * \brief Read PID from given file.
 *
 * \param fn Filename containing PID.
 *
 * \retval PID on success.
 * \retval negative integer on error.
 */
pid_t pid_read(const char* fn);

/*!
 * \brief Write PID to given file.
 *
 * \param fn Filename containing PID.
 *
 * \retval 0 on success.
 * \retval negative integer on error.
 */
int pid_write(const char* fn);

/*!
 * \brief Remove file containing PID.
 *
 * \param fn Filename containing PID.
 *
 * \warning Filename content won't be checked.
 *
 * \retval 0 on success.
 * \retval negative integer on error.
 */
int pid_remove(const char* fn);

#endif // _KNOT_PROCESS_H_
