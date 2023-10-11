#!/usr/bin/env python3

# This package is needed on Debian derived ditributions: python3-dasbus

import argparse
import socket
import dasbus.connection
import dasbus.loop
import signal
import sys
import time

def sig_started(sender, path, interface, signal, args):
    print("Server started")

def sig_stopped(sender, path, interface, signal, args):
    print("Server stopped")

def sig_updated(sender, path, interface, signal, args):
    (zone, serial) = args
    print("Updated zone=%s to serial=%d" % (zone, serial))

def sig_keys_upd(sender, path, interface, signal, args):
    (zone) = args
    print("Keys updated for zone=%s" % (zone))

def sig_submission(sender, path, interface, signal, args):
    (zone, key_tag, kasp_id) = args
    print("Ready KSK for zone=%s keytag=%u keyid=%s" % (zone, key_tag, kasp_id))

def sig_invalid(sender, path, interface, signal, args):
    (zone) = args
    print("Invalid DNSSEC for zone=%s" % (zone))

if __name__ == '__main__':
    loop = dasbus.loop.EventLoop()

    def sigint_handler(sig, frame):
        loop.quit()
        sys.exit()

    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser(
        description="A D-Bus client for processing signals emitted by knotd",
    )
    parser.add_argument(
        "-s",
        "--socket",
        nargs="?",
        help="optional address of D-Bus UNIX socket (e.g. '/rundir/dbus.sock'); " +
             "note that the caller's UID must exist in the remote system " +
             "(due to D-Bus EXTERNAL authentication)"
    )
    args = parser.parse_args()

    if args.socket:
        while True:  # Wait until specified D-Bus socket can be used
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            result = s.connect_ex(args.socket)
            s.close()
            if not result:
                break
            time.sleep(0.5)
        bus = dasbus.connection.AddressedMessageBus(address="unix:path=" + args.socket)
    else:
        bus = dasbus.connection.SystemMessageBus()

    def connect_to_signal(_signal, _callback):
        bus.connection.signal_subscribe(
            "cz.nic.knotd",
            "cz.nic.knotd.events",
            _signal,
            "/cz/nic/knotd",
            None,
            0,
            lambda _, sender, path, interface, signal, args: _callback(
                sender, path, interface, signal, args.unpack()
            ),
        )

    connect_to_signal("started", sig_started)
    connect_to_signal("stopped", sig_stopped)
    connect_to_signal("zone_updated", sig_updated)
    connect_to_signal("keys_updated", sig_keys_upd)
    connect_to_signal("zone_ksk_submission", sig_submission)
    connect_to_signal("zone_dnssec_invalid", sig_invalid)

    loop.run()
