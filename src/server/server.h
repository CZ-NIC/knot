/*!
 * @file server.h
 *
 * Contains the main high-level server structure (cute_server) and interface
 * to functions taking care of proper initialization of the server and clean-up
 * when terminated.
 *
 * As of now, the server supports only one zone file and only in a special
 * format.
 *
 * @see zone-parser.h
 */
#ifndef SERVER
#define SERVER

#include "dispatcher.h"
#include "socket-manager.h"
#include "zone-database.h"
#include "name-server.h"
#include "common.h"

/*----------------------------------------------------------------------------*/
/*!
 * @brief Main server structure. Keeps references to all important structures
 *        needed for operation.
 */
typedef struct cute_server {

	/*! @brief Reference to the socket manager structures. */
	 sm_manager* manager[SERVER_MGR_COUNT];

	/*! @brief Reference to the name server structure. */
    ns_nameserver *nameserver;

	/*! @brief Reference to the zone database structure. */
    zdb_database *zone_db;

    /*! @brief @todo Server should have some state tracking.
    uint state;
    */
} cute_server;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Allocates and initializes the server structure. Creates all other
 *        main structures
 */
cute_server *cute_create();

/*!
 * @brief Starts the server.
 *
 * @param server Server structure to be used for operation.
 * @param filename Zone file name to be used by the server.
 *
 * @retval 0 On success.
 * @retval -1 If an error occured.
 *
 * @todo When a module for configuration is added, the filename parameter will
 *       be removed.
 */
int cute_start( cute_server *server, char **filenames, uint zones );

/*!
 * @brief Waits for the server to finish.
 *
 * @param server Server structure to be used for operation.
 *
 * @retval 0 On success.
 * @retval -1 If an error occured.
 *
 */
int cute_wait(cute_server *server);

/*!
 * @brief Requests server to stop.
 */
void cute_stop( cute_server *server );

/*!
 * @brief Properly destroys the server structure.
 */
void cute_destroy( cute_server **server );

/*----------------------------------------------------------------------------*/

#endif
