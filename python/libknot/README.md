# Libknot API in Python

A Python interface for managing the Knot DNS daemon.

# Table of contents

* [Introduction](#introduction)
* [Control module](#control-module)
  + [Usage](#using-the-control-module)
  + [Example](#control-module-example)
* [Probe module](#probe-module)
  + [Usage](#using-the-probe-module)
  + [Example](#probe-module-example)
* [Dname module](#dname-module)
  + [Usage](#using-the-dname-module)
  + [Example](#dname-module-example)

## Introduction

If the shared `libknot.so` library isn't available in the library search path, it's
necessary to load the library first, e.g.:

```python3
import libknot
libknot.Knot("/usr/lib/libknot.so")
```

## Control module

Using this module it's possible to create scripts for efficient tasks that
would require complex shell scripts with multiple calls of `knotc`. For
communication with the daemon it uses the same mechanism as the `knotc` utility,
i.e. communication via a Unix socket.

The module API is stored in `libknot.control`.

### Using the Control module

The module usage consists of several steps:

* Initialization and connection to the daemon control socket.
* One or more control operations. An operation is called by sending a command
  with optional data to the daemon. The operation result has to be received
  afterwards.
* Closing the connection and deinitialization.

### Control module example

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
    ctl.send_block(cmd="conf-list", flags="z")
    resp = ctl.receive_block()
    for zone in resp['zone']:
        print(zone)
```

```python3
    # Print expirations as unixtime for all secondary zones
    ctl.send_block(cmd="zone-status", flags="u")
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

## Probe module

Using this module it's possible to receive traffic data from a running daemon with
active probe module.

The module API is stored in `libknot.probe`.

### Using the Probe module

The module usage consists of several steps:

* Initialization of one or more probe channels
* Periodical receiving of data units from the channels and data processing

### Probe module example

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

## Dname module

This module provides a few dname-related operations.

### Using the Dname module

The dname object is initialized from a string with textual dname.
Then the dname can be reformatted to wire format or back to textual format.

### Dname module example

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
