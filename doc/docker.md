# Shared volumes
- `config` - Server configuration file location
- `storage` - Zone data, KASP storage, and server configuration database location
- `rundir` - Server control socket, PID file, and D-Bus socket location

# Examples
- DNS queries:

 `docker run --rm cznic/knot kdig @1.1.1.1 knot-dns.cz`

 `docker run --rm cznic/knot kdig @dns.adguard.com AAAA knot-dns.cz +dnssec +quic`

- Controllable server with persistent configuration DB:

 `docker run --rm -v /tmp/storage:/storage cznic/knot knotc conf-init`

 `docker run --rm -v /tmp/storage:/storage -v /tmp/rundir:/rundir --network host -d cznic/knot knotd`

 `docker run -it --rm -v /tmp/rundir:/rundir cznic/knot knotc`

  knotc> `conf-begin`

  knotc> `conf-set server.listen 127.0.0.1@5300`

  knotc> `conf-commit`

  knotc> `exit`

 `kdig @127.0.0.1 -p5300 ch txt version.server`

 `docker run --rm -v /tmp/rundir:/rundir cznic/knot knotc stop`

- For zone events signaling, the D-Bus daemon must be executed first:

 `docker run --rm -v /tmp/storage:/storage -v /tmp/rundir:/rundir --network host -d cznic/knot sh -c "dbus-daemon --system; knotd"`
