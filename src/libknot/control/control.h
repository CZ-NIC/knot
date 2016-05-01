/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 *
 * \brief A server control interface.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

/*! Control data item indexes. */
typedef enum {
	KNOT_CTL_IDX_CMD = 0, /*!< Control command name. */
	KNOT_CTL_IDX_FLAGS,   /*!< Control command flags. */
	KNOT_CTL_IDX_ERROR,   /*!< Error message. */
	KNOT_CTL_IDX_SECTION, /*!< Configuration section name. */
	KNOT_CTL_IDX_ITEM,    /*!< Configuration item name. */
	KNOT_CTL_IDX_ID,      /*!< Congiguration item identifier. */
	KNOT_CTL_IDX_ZONE,    /*!< Zone name. */
	KNOT_CTL_IDX_OWNER,   /*!< Zone record owner */
	KNOT_CTL_IDX_TTL,     /*!< Zone record TTL. */
	KNOT_CTL_IDX_TYPE,    /*!< Zone record type name. */
	KNOT_CTL_IDX_DATA,    /*!< Configuration item/zone record data. */
	KNOT_CTL_IDX__COUNT,  /*!< The number of data items. */
} knot_ctl_idx_t;

/*! Control unit types. */
typedef enum {
	KNOT_CTL_TYPE_END,   /*!< End of message, cache flushed. */
	KNOT_CTL_TYPE_DATA,  /*!< Data unit, cached. */
	KNOT_CTL_TYPE_EXTRA, /*!< Extra value data unit, cached. */
	KNOT_CTL_TYPE_BLOCK, /*!< End of data block, cache flushed. */
} knot_ctl_type_t;

/*! Control input/output string data. */
typedef const char* knot_ctl_data_t[KNOT_CTL_IDX__COUNT];

/*! A control context. */
struct knot_ctl;
typedef struct knot_ctl knot_ctl_t;

/*!
 * Allocates a control context.
 *
 * \return Control context.
 */
knot_ctl_t* knot_ctl_alloc(void);

/*!
 * Deallocates a control context.
 *
 * \param[in] ctx  Control context.
 */
void knot_ctl_free(knot_ctl_t *ctx);

/*!
 * Sets the timeout for socket operations.
 *
 * Default value is 5 seconds.
 *
 * \param[in] ctx      Control context.
 * \param[in] timeout  Timeout in milliseconds (0 for infinity).
 */
void knot_ctl_set_timeout(knot_ctl_t *ctx, int timeout_ms);

/*!
 * Binds a specified UNIX socket path.
 *
 * \note Server operation.
 *
 * \param[in] ctx   Control context.
 * \param[in] path  Control UNIX socket path.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_ctl_bind(knot_ctl_t *ctx, const char *path);

/*!
 * Unbinds a control socket.
 *
 * \note Server operation.
 *
 * \param[in] ctx  Control context.
 */
void knot_ctl_unbind(knot_ctl_t *ctx);

/*!
 * Connects to a specified UNIX socket path.
 *
 * \note Client operation.
 *
 * \param[in] ctx   Control context.
 * \param[in] path  Control UNIX socket path.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_ctl_connect(knot_ctl_t *ctx, const char *path);

/*!
 * Waits for an incoming connection.
 *
 * \note Server operation.
 *
 * \param[in] ctx  Control context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_ctl_accept(knot_ctl_t *ctx);

/*!
 * Closes the remote connections.
 *
 * \note Applies to both server and client.
 *
 * \param[in] ctx  Control context.
 */
void knot_ctl_close(knot_ctl_t *ctx);

/*!
 * Sends one control unit.
 *
 * \param[in] ctx   Control context.
 * \param[in] type  Unit type to send.
 * \param[in] data  Data unit to send (optional, ignored if non-data type).
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_ctl_send(knot_ctl_t *ctx, knot_ctl_type_t type, knot_ctl_data_t *data);

/*!
 * Receives one control unit.
 *
 * \param[in] ctx    Control context.
 * \param[out] type  Received unit type.
 * \param[out] data  Received data unit (optional).
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_ctl_receive(knot_ctl_t *ctx, knot_ctl_type_t *type, knot_ctl_data_t *data);

/*! @} */
