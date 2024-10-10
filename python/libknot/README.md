# Libknot API in Python

A Python interface for managing the Knot DNS daemon.

# Table of contents

* [Introduction](#introduction)
* [Control module](#control-module)
  + [Control usage](#control-usage)
  + [Control examples](#control-examples)
  + [Control API](#control-api)
* [Probe module](#probe-module)
  + [Probe usage](#probe-usage)
  + [Probe examples](#probe-examples)
* [Dname module](#dname-module)
  + [Dname usage](#dname-usage)
  + [Dname examples](#dname-examples)

## Introduction<a id="introduction"></a>

If the shared `libknot.so` library isn't available in the library search path, it's
necessary to load the library first, e.g.:

```python3
import libknot
libknot.Knot("/usr/lib/libknot.so")
```

## Control module<a id="control-module"></a>

Using this module it's possible to create scripts for efficient tasks that
would require complex shell scripts with multiple calls of `knotc`. For
communication with the daemon it uses the same mechanism as the `knotc` utility,
i.e. communication via a Unix socket.

The module API is stored in `libknot.control`.

### Control usage<a id="control-usage"></a>

The module usage consists of several steps:

* Initialization and connection to the daemon control socket.
* One or more control operations. An operation is called by sending a command
  with optional data to the daemon. The operation result has to be received
  afterwards.
* Closing the connection and deinitialization.

### Control examples<a id="control-examples"></a>

```python3
import json
import libknot.control

# Initialization
ctl = libknot.control.KnotCtl()
ctl.connect("/var/run/knot/knot.sock")
ctl.set_timeout(60)

try:
    # Operation without parameters
    ctl.send_block(cmd="conf-begin")
    resp = ctl.receive_block()

    # Operation with parameters
    ctl.send_block(cmd="conf-set", section="zone", item="domain", data="test")
    resp = ctl.receive_block()

    ctl.send_block(cmd="conf-commit")
    resp = ctl.receive_block()

    # Operation with a result displayed in JSON format
    ctl.send_block(cmd="conf-read", section="zone", item="domain")
    resp = ctl.receive_block()
    print(json.dumps(resp, indent=4))
except libknot.control.KnotCtlError as exc:
    # Print libknot error
    print(exc)
finally:
    # Deinitialization
    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()
```

```python3
    # List configured zones (including catalog member ones)
    ctl.send_block(cmd="conf-list", filters="z")
    resp = ctl.receive_block()
    for zone in resp['zone']:
        print(zone)
```

```python3
    # Print expirations as unixtime for all secondary zones
    ctl.send_block(cmd="zone-status", filters="u")
    resp = ctl.receive_block()
    for zone in resp:
        if resp[zone]["role"] == "master":
            continue

        expiration = resp[zone]["expiration"]
        if expiration == "-":
            print("Zone %s not loaded" % zone)
        else:
            print("Zone %s expires at %s" % (zone, resp[zone]["expiration"]))
```

### Control API<a id="control-api"></a>

[commands](https://www.knot-dns.cz/docs/latest/html/man_knotc.html#actions)

 status             [<detail>]                             Check if the server is running.
 stop                                                      Stop the server if running.
 reload                                                    Reload the server configuration and modified zones.
 stats              [<module>[.<counter>]]                 Show global statistics counter(s).

 zone-status        [<zone>...] [<filter>...]              Show the zone status.
 zone-reload        [<zone>...]                            Reload a zone from a disk. (#)
 zone-refresh       [<zone>...]                            Force slave zone refresh. (#)
 zone-notify        [<zone>...]                            Send a NOTIFY message to all configured remotes. (#)
 zone-retransfer    [<zone>...]                            Force slave zone retransfer (no serial check). (#)
 zone-flush         [<zone>...] [<filter>...]              Flush zone journal into the zone file. (#)
 zone-backup        [<zone>...] [<filter>...] +backupdir <dir> Backup zone data and metadata. (#)
 zone-restore       [<zone>...] [<filter>...] +backupdir <dir> Restore zone data and metadata. (#)
 zone-sign          [<zone>...]                            Re-sign the automatically signed zone. (#)
 zone-validate      [<zone>...]                            Trigger a DNSSEC validation of the zone. (#)
 zone-keys-load     [<zone>...]                            Re-load keys from KASP database, sign the zone. (#)
 zone-key-rollover   <zone> ksk|zsk                        Trigger immediate key rollover. (#)
 zone-ksk-submitted  <zone>...                             When KSK submission, confirm parent's DS presence. (#)
 zone-freeze        [<zone>...]                            Temporarily postpone automatic zone-changing events. (#)
 zone-thaw          [<zone>...]                            Dismiss zone freeze. (#)
 zone-xfr-freeze    [<zone>...]                            Temporarily disable outgoing AXFR/IXFR. (#)
 zone-xfr-thaw      [<zone>...]                            Dismiss outgoing XFR freeze. (#)

 zone-read          <zone> [<owner> [<type>]]              Get zone data that are currently being presented.
 zone-begin         <zone>...                              Begin a zone transaction.
 zone-commit        <zone>...                              Commit the zone transaction.
 zone-abort         <zone>...                              Abort the zone transaction.
 zone-diff          <zone>                                 Get zone changes within the transaction.
 zone-get           <zone> [<owner> [<type>]]              Get zone data within the transaction.
 zone-set           <zone>  <owner> [<ttl>] <type> <rdata> Add zone record within the transaction.
 zone-unset         <zone>  <owner> [<type> [<rdata>]]     Remove zone data within the transaction.
 zone-purge         <zone>... [<filter>...]                Purge zone data, zone file, journal, timers, and KASP data. (#)
 zone-stats         <zone> [<module>[.<counter>]]          Show zone statistics counter(s).

 conf-list          [<item>...]                            List the confdb sections or section items.
 conf-read          [<item>...]                            Get the item from the active confdb.
 conf-begin         [+benevolent]                          Begin a writing confdb transaction.
 conf-commit                                               Commit the confdb transaction.
 conf-abort                                                Rollback the confdb transaction.
 conf-diff          [<item>...]                            Get the item difference within the transaction.
 conf-get           [<item>...]                            Get the item data within the transaction.
 conf-set            <item>  [<data>...]                   Set the item data within the transaction.
 conf-unset         [<item>] [<data>...]                   Unset the item data within the transaction.

## Probe module<a id="probe module"></a>

Using this module it's possible to receive traffic data from a running daemon with
active probe module.

The module API is stored in `libknot.probe`.

### Probe usage<a id="probe-usage"></a>

The module usage consists of several steps:

* Initialization of one or more probe channels
* Periodical receiving of data units from the channels and data processing

### Probe examples<a id="probe-examples"></a>

```python3
import libknot.probe

# Initialization of the first probe channel stored in `/run/knot`
probe = libknot.probe.KnotProbe("/run/knot", 1)

# Array for storing up to 8 data units
data = libknot.probe.KnotProbeDataArray(8)
while (True):
    # Receiving data units with timeout of 1000 ms
    if probe.consume(data, 1000) > 0:
        # Printing received data units in the default format
        for item in data:
            print(item)
```

## Dname module<a id="dname-module"></a>

This module provides a few dname-related operations.

The module API is stored in `libknot.dname`.

### Dname usage<a id="dname-usage"></a>

The dname object is initialized from a string with textual dname.
Then the dname can be reformatted to wire format or back to textual format.

### Dname examples<a id="dname-examples"></a>

```python3
import libknot.dname

dname1 = libknot.dname.KnotDname("knot-dns.cz")
print("%s: wire: %s size: %u" % (dname1.str(), dname1.wire(), dname1.size()))

dname2 = libknot.dname.KnotDname("e\\120ample.c\om.")
print("%s: wire: %s size: %u" % (dname2.str(), dname2.wire(), dname2.size()))

dname3 = libknot.dname.KnotDname(dname_wire=b'\x02cz\x00')
print("%s: wire: %s size: %u" % (dname3.str(), dname3.wire(), dname3.size()))
```

```bash
knot-dns.cz.: wire: b'\x08knot-dns\x02cz\x00' size: 13
example.com.: wire: b'\x07example\x03com\x00' size: 13
cz.: wire: b'\x02cz\x00' size: 4
```
