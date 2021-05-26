# Libknot API in Python

## Control API

Example:

```python3
import json
import libknot.control

#import libknot
#libknot.Knot("/usr/lib/libknot.so")

ctl = libknot.control.KnotCtl()
ctl.connect("/var/run/knot/knot.sock")

try:
    ctl.send_block(cmd="conf-begin")
    resp = ctl.receive_block()

    ctl.send_block(cmd="conf-set", section="zone", item="domain", data="test")
    resp = ctl.receive_block()

    ctl.send_block(cmd="conf-commit")
    resp = ctl.receive_block()

    ctl.send_block(cmd="conf-read", section="zone", item="domain")
    resp = ctl.receive_block()
    print(json.dumps(resp, indent=4))
finally:
    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()
```

## Probe API

Example:

```python3
import libknot.probe

#import libknot
#libknot.Knot("/usr/lib/libknot.so")

probe = libknot.probe.KnotProbe("/run/knot")

data = libknot.probe.KnotProbeDataArray(8)
while (True):
    if probe.consume(data) > 0:
        for item in data:
            print(item)
```
