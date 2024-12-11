# Libknot API in Python

A Python interface for managing the Knot DNS daemon.

# Table of contents

* [Introduction](#introduction)
* [Control module](#control-module)
  + [Protocol reference](#kctl-proto)
  + [Commands reference](#kctl-cmds)
  + [Usage](#control-usage)
  + [Examples](#control-examples)
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

### Protocol overview<a id="kctl-proto"></a>

Connections are supposed to be short-lived, because maintaining a passive
connection is costly for the server. Therefore the expected usage of the control
interface is to always open a new connection on demand, then close it once it's
not immediately needed.

Messages are composed of units. These are of four types the identifiers of
which are defined in `libknot.control.KnotCtlType`:

| Type    | Description                                                | IO action |
| ------- | ---------------------------------------------------------- | --------- |
| `END`   | Signals intent to terminate connection.                    | flush     |
| `DATA`  | Holds various information - see about data sections below. | cache     |
| `EXTRA` | Additional data.                                           | cache     |
| `BLOCK` | End of data block.                                         | flush     |

`DATA` and `EXTRA` units aren't immediately sent, rather they're buffered and
then sent along with the next `END` or `BLOCK` unit.

A unit can optionaly hold data, though this is only meaningful for the `DATA`
and `EXTRA` types. The data consists of several sections of which usually only
a few at a time will be present. For example when a unit issuing a `stats`
command is sent, there is no reason for it to contain an `ID` section.

The data section identifiers are defined in `libknot.control.KnotCtlDataIdx`:

| Section name | `send_block()` arg name | Description                                            |
| ------------ | ----------------------- | ------------------------------------------------------ |
| `COMMAND`    | cmd                     | Command name.                                          |
| `FLAGS`      | flags                   | Command flags.                                         |
| `ERROR`      | *(n/a)*                 | Error message. Only sent by the server.                |
| `SECTION`    | section                 | Configuration section name.                            |
| `ITEM`       | item                    | Configuration item name.                               |
| `ID`         | identifier              | Configuration item identifier.                         |
| `ZONE`       | zone                    | Zone name.                                             |
| `OWNER`      | owner                   | Zone record owner                                      |
| `TTL`        | ttl                     | Zone record TTL.                                       |
| `TYPE`       | rtype                   | Zone record type name.                                 |
| `DATA`       | data                    | Configuration item/zone record data.                   |
| `FILTERS`    | filters                 | Command options or filters for output data processing. |

### Commands reference<a id="kctl-cmds"></a>

The following is a reference for the low-level control API. In case you're unsure
of the commands' semantics, please consult the
<a href="https://www.knot-dns.cz/docs/latest/singlehtml/index.html#actions">knotc documentation</a>.

A concise notation is used for command synopsis:

```
# command "cmd-name" accepts section of type SECTION_NAME and optionally
# another section of type OPT_SECTION
cmd-name(SECTION_NAME, [OPT_SECTION])

[OPT_SECTION="literal value"],   # Optional section with fixed expected value.
[SECTION1, SECTION2]             # Sections must be present together or not at all.
[SECTION1, [SECTION2]]           # SECTION2 may only appear if SECTION1 is present.
SECTION_NAME="option1"|"option2" # Either one or the other literal may be used.
SECTION_NAME={"asdf"}            # Any subset of characters may be used.
```

The `B` flag always represents an option to execute in blocking mode.

When listing the filters a command accepts, the letter which is passed into
`FILTERS` will be boldened. Like this: zone**f**ile

#### Server

* `status([TYPE="cert-key"|"configure"|"version"|"workers"])`
* `stop()`
* `reload()`
* `stats([SECTION, [ITEM]], [FLAGS="F"])`
  + `SECTION` stores the module, `ITEM` stores the counter
  + the `F` flag specifies to include 0 counters in server's response

#### Zone events

The following commands apply to all zones if `ZONE` is left empty.

* `zone-status([ZONE], [FILTERS={"rstefc"}])`
  + filters: **r**ole, **s**erial, **t**ransaction, **e**vents, **f**reeze, **c**atalog <!-- , **u**nixtime -->
* `zone-reload([ZONE], [FLAGS={"BF"}])`
  + the `F` flag commands to also reload modules
* `zone-refresh([ZONE], [FLAGS="B"])`
* `zone-retransfer([ZONE], [FLAGS="B"])`
* `zone-notify([ZONE], [FLAGS="B"])`
* `zone-flush([ZONE], [FILTERS="d", DATA], [FLAGS={"FB"}])`
  + the output**d**ir filter commands that zone(s) be flushed to path stored in the `DATA` section
  + the `F` flag is required if zonefile synchronization is disabled
* `zone-backup([ZONE], [FILTERS={"dzjtkocqZJTKOCQ"}, [DATA]], [FLAGS="B"])`
  + filters
    - the backup**d**ir filter commands that backups be made to path stored in the `DATA` section
    - **z**onefile, **j**ournal, **t**imers, **k**aspdb, keys**o**nly, **c**atalog, **q**uic
    - negative counterparts (eg. no**Z**onefile) are symmetrical and capitalized
  + the `F` flag allows for an existing backupdir to be overwritten
* `zone-restore` *analogous to `zone-backup`*
* `zone-sign([ZONE], [FLAGS="B"])`
* `zone-validate([ZONE], [FLAGS="B"])`
* `zone-keys-load([ZONE], [FLAGS="B"])`
* `zone-key-rollover([ZONE], TYPE="ksk"|"zsk", [FLAGS="B"])`
* `zone-ksk-submitted([ZONE], [FLAGS="B"])`
* `zone-freeze([ZONE], [FLAGS="B"])`
* `zone-thaw([ZONE], [FLAGS="B"])`
* `zone-xfr-freeze([ZONE], [FLAGS="B"])`
* `zone-xfr-thaw([ZONE], [FLAGS="B"])`

#### Zone editing

Use `@` as `OWNER` if you want to denote `ZONE` itself as the owner.

* `zone-read([ZONE], [OWNER], [TYPE])`
  + if `ZONE` is left empty all zones are read
* `zone-begin(ZONE, [FILTERS="b"])`
  + filters: **b**enevolent
* `zone-commit([ZONE])`
* `zone-abort([ZONE])`
* `zone-diff([ZONE])`
* `zone-get([ZONE], [OWNER], [TYPE])`
* `zone-set([ZONE], OWNER, [TTL], TYPE, DATA)`
* `zone-unset([ZONE], OWNER, [TYPE, [DATA]])`
* `zone-purge([ZONE], [FILTERS={ocejktf}], [FLAGS="B"])`
  + filters: **o**rphan, **c**atalog, **e**xpire, **j**ournal, **k**aspdb, **t**imers, zone**f**ile
* `zone-stats([ZONE], [SECTION, [ITEM]], [FLAGS="F"])`
  + `SECTION` stores the module, `ITEM` stores the counter
  + the `F` flag specifies to include 0 counters in server's response

#### Configuration

For the following commands:

* `SECTION` holds the configuration section name (eg. `template`)
* `ID` holds the configuration id (eg. `default`)
* `ITEM` holds the configuration item name (eg. `storage`)

<!-- hacky comment to separate markdown lists -->

* `conf-list([SECTION, [ID], [ITEM]], [FILTERS="z"|{"st"}])`
  + filters:
    - **z**one: list all zone names, including those from the catalog
    - li**s**t: list configuration section items instead of its identifiers
    - **t**ransaction: If a transaction is open (`conf-begin`) queries the
      transaction's configuration schema instead of the server's
* `conf-read([SECTION, [ID], [ITEM]])`
* `conf-begin()`
* `conf-commit()`
* `conf-abort()`
* `conf-diff([SECTION, [ID], [ITEM]])`
* `conf-get([SECTION, [ID], [ITEM]])`
* `conf-set(SECTION, ID, ITEM, [DATA])`
* `conf-unset([SECTION, [ID], [ITEM], [DATA]])`
  + `DATA` may only be meaningfully specified if the preceding sections are as well

### Control usage<a id="control-usage"></a>

The module usage consists of several steps:

* Initialization and connection to the daemon control socket.
* One or more control operations. An operation is called by sending a command
  with optional data to the daemon. The operation result has to be received
  afterwards.
* Closing the connection and deinitialization.

#### Sending

There are two methods on the `KnotCtl` class which send data to the socket.

`KnotCtl.send(KnotCtlType, KnotCtlData)` is the more rudimentary one. It only
sends the section identifier along with its data, if any are provided. When
using this function users must beware of the different characteristics
regarding buffering of different unit types.

`KnotCtl.send_block(...)` is more convenient in that it always flushes by
sending a `BLOCK` unit. Otherwise the two methods are functionally equivalent.

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
