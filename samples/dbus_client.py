#!/usr/bin/env python3

import dbus
import dbus.mainloop.glib
import signal
from gi.repository import GLib

def sigint_handler(sig, frame):
    if sig == signal.SIGINT:
        loop.quit()
    else:
        raise ValueError("Undefined handler for '{}'".format(sig))

def updated(*args, **kwargs):
    (zone, serial) = args
    print("Zone %s updated, SOA serial %d" % (zone, serial))

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)

    loop = dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    knotd = bus.get_object('cz.nic.knotd', '/cz/nic/knotd', introspect=False)
    events_iface = dbus.Interface(knotd, dbus_interface='cz.nic.knotd.events')
    events_iface.connect_to_signal("zone_updated", updated)
    loop = GLib.MainLoop()
    loop.run()
