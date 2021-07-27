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
finally:
    # Deinitialization
    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()
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
