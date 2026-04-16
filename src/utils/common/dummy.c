/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*
 * Dummy symbols for external dependencies that aren't accessed from kdig.
 */

#include "libzscanner/error.h"
#include "libzscanner/scanner.h"

int zs_init(
	zs_scanner_t *scanner,
	const char *origin,
	const uint16_t rclass,
	const uint32_t ttl
) { return 0; }

void zs_deinit(
	zs_scanner_t *scanner
) { }

int zs_set_input_string(
	zs_scanner_t *scanner,
	const char *input,
	size_t size
) { return 0; }

int zs_set_input_file(
	zs_scanner_t *scanner,
	const char *file_name
) { return 0; }

int zs_set_processing(
	zs_scanner_t *scanner,
	void (*process_record)(zs_scanner_t *),
	void (*process_error)(zs_scanner_t *),
	void *data
) { return 0; }

int zs_parse_record(
	zs_scanner_t *scanner
) { return 0; }

int zs_parse_all(
	zs_scanner_t *scanner
) { return 0; }

const char* zs_strerror(const int code) { return NULL; }

////

#include <urcu.h>

#if defined(rcu_read_lock_memb)
void urcu_memb_call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head)) { }
void urcu_memb_read_lock(void) { }
void urcu_memb_read_unlock(void) { }
void urcu_memb_synchronize_rcu(void) { }
void urcu_memb_register_thread(void) { }
void urcu_memb_unregister_thread(void) { }
void *rcu_xchg_pointer_sym(void **p, void *v) { return NULL; }
#else // Needed for CentOS 8
void call_rcu_memb(struct rcu_head *head, void (*func)(struct rcu_head *head)) { }
void rcu_read_lock_memb(void) { }
void rcu_read_unlock_memb(void) { }
void synchronize_rcu_memb(void) { }
void rcu_register_thread_memb(void) { }
void rcu_unregister_thread_memb(void) { }
void *rcu_xchg_pointer_sym(void **p, void *v) { return NULL; }
#endif // rcu_read_lock_memb

////

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-journal.h>
#include <systemd/sd-daemon.h>

int sd_booted(void) { return 0; }
#undef sd_journal_send
int sd_journal_send(const char *format, ...) { return 0; }
int sd_journal_send_with_location(const char *file, const char *line, const char *func, const char *format, ...) { return 0; }
#endif // ENABLE_SYSTEMD

////

#if defined(ENABLE_DBUS_SYSTEMD)
#include <systemd/sd-bus.h>

int sd_bus_open_system(sd_bus **ret) { return 0; }
int sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags) { return 0; }
int sd_bus_send(sd_bus *bus, sd_bus_message *m, uint64_t *cookie) { return 0; }
sd_bus* sd_bus_unref(sd_bus *bus) { return NULL; }
int sd_bus_message_new_signal(sd_bus *bus, sd_bus_message **m, const char *path, const char *interface, const char *member) { return 0; }
int sd_bus_message_appendv(sd_bus_message *m, const char *types, va_list ap) { return 0; }
sd_bus_message* sd_bus_message_unref(sd_bus_message *m) { return NULL; }
sd_bus* sd_bus_message_get_bus(sd_bus_message *m) { return NULL; }

#elif defined(ENABLE_DBUS_LIBDBUS)
#include <dbus/dbus.h>

void dbus_error_init(DBusError *error) { }
dbus_bool_t dbus_error_is_set(const DBusError *error) { return 0; }
void dbus_error_free(DBusError *error) { }
DBusConnection* dbus_bus_get(DBusBusType type, DBusError *error) { return NULL; }
int dbus_bus_request_name(DBusConnection *connection,
                          const char *name,
                          unsigned int flags,
                          DBusError *error) { return 0; }
void dbus_connection_unref(DBusConnection *connection) { }
DBusMessage* dbus_message_new_signal(const char *path,
                                     const char *interface,
                                     const char *name) { return NULL; }
dbus_bool_t dbus_message_append_args(DBusMessage *message, int first_arg_type, ...) { return 0; }
dbus_bool_t dbus_connection_send(DBusConnection *connection,
                                 DBusMessage *message,
                                 dbus_uint32_t *client_serial) { return 0; }
void dbus_message_unref(DBusMessage *message) { }

#endif // ENABLE_DBUS_LIBDBUS

////

#ifdef ENABLE_REDIS
#include <hiredis/hiredis.h>

void redisFree(redisContext *c) { }
redisContext *redisConnectWithTimeout(const char *ip, int port, const struct timeval tv) { return NULL; }
void *redisCommand(redisContext *c, const char *format, ...) { return NULL; }
int redisAppendCommand(redisContext *c, const char *format, ...) { return 0; }
int redisGetReply(redisContext *c, void **reply) { return 0; }
void freeReplyObject(void *reply) { }
int redisBufferWrite(redisContext *c, int *done) { return 0; }
redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv) { return NULL; }

#ifdef ENABLE_REDIS_TLS
#include <hiredis/alloc.h>
struct hiredisAllocFuncs hiredisAllocFns = { };
#endif // ENABLE_REDIS_TLS

#endif // ENABLE_REDIS
