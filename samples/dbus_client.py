#!/usr/bin/env python3

# This package is needed on Debian derived ditributions: python3-dbus

import dbus
import dbus.mainloop.glib
import signal
import time
from gi.repository import GLib

def sigint_handler(sig, frame):
    if sig == signal.SIGINT:
        loop.quit()
    else:
        raise ValueError("Undefined handler for '{}'".format(sig))

def sig_started(*args, **kwargs):
    print("Server started")

def sig_stopped(*args, **kwargs):
    print("Server stopped")

def sig_updated(*args, **kwargs):
    (zone, serial) = args
    print("Updated zone=%s to serial=%d" % (zone, serial))

def sig_submission(*args, **kwargs):
    (zone, key_tag, kasp_id) = args
    print("Ready KSK for zone=%s keytag=%u keyid=%s" % (zone, key_tag, kasp_id))

def sig_invalid(*args, **kwargs):
    (zone) = args
    print("Invalid DNSSEC for zone=%s" % (zone))

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)

    loop = dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    bus = dbus.SystemBus()
    while True: # Wait until the service (knotd) is ready.
        try:
            knotd = bus.get_object('cz.nic.knotd', '/cz/nic/knotd',
                                   follow_name_owner_changes=True,
                                   introspect=False)
            break
        except:
            time.sleep(0.1)
    events_iface = dbus.Interface(knotd, dbus_interface='cz.nic.knotd.events')
    events_iface.connect_to_signal("started", sig_started)
    events_iface.connect_to_signal("stopped", sig_stopped)
    events_iface.connect_to_signal("zone_updated", sig_updated)
    events_iface.connect_to_signal("zone_ksk_submission", sig_submission)
    events_iface.connect_to_signal("zone_dnssec_invalid", sig_invalid)

    loop = GLib.MainLoop()
    loop.run()
