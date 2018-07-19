.. _mod-geoip:

``geoip`` — Geography-based responses
=====================================

This module offers response tailoring based on client's
subnet or geographic location. It supports GeoIP databases
in the MaxMind DB format, such as `GeoIP2 <https://dev.maxmind.com/geoip/geoip2/downloadable/>`_
or the free version `GeoLite2 <https://dev.maxmind.com/geoip/geoip2/geolite2/>`_.
Furthermore, if queries contain EDNS Client Subnet option as per :rfc:`7871`,
the module takes advantage of this information to provide more accurate responses.

The module can be enabled only per zone.

.. NOTE::
   If dnssec-signing is enabled, RRs returned from the module are signed by the
   zone's ZSK when the module is loaded. It is STRONGLY RECOMMENDED to use
   this setting only with manual key rollover, since the module has to be
   reloaded when the zone's signing key changes.

.. NOTE::
   The module is meant to provide RRsets alternative to those already present in
   the given zone, i.e. for any location-specific RRset,
   there should also be a **default** RRset of the same type present in the zone
   and returned to clients which do not fall into any of the configured locations.
   This is especially important if DNSSEC is enabled, to ensure that the NSEC-chain
   is built correctly.

Example
-------
* An example configuration.::

   mod-geoip:
     - id: default
       config-file: /path/to/geo.conf
       ttl: 20
       mode: geodb
       geodb-file: /path/to/GeoLite2-City.mmdb
       geodb-key: [ country/iso_code, city/names/en ]

   zone:
     - domain: example.com.
       module: mod-geoip/default


* The module requires an additional configuration file specifying
  the desired responses to clients querying from specific subnets::

   foo.example.com:
     - subnet: 10.0.0.0/24
       A: [ 192.168.1.1, 192.168.1.2 ]
       AAAA: [ 2001:DB8::1, 2001:DB8::2 ]
       TXT: "subnet 10.0.0.0/24"
     ...
   bar.example.com:
     - subnet: 2001:DB8::/32
       A: 192.168.1.3
       AAAA: 2001:DB8::3
       TXT: "subnet 2001:DB8::/32"
   ...

  or geographic locations::

   foo.example.com:
     - geo: "CZ;Prague"
       CNAME: foo.example.org
     - geo: "US;Las Vegas"
       CNAME: foo.example.net
   ...

Module reference
----------------

::

 mod-geoip:
   - id: STR
     config-file: STR
     ttl: TIME
     mode: geodb | subnet
     geodb-file: STR
     geodb-key: STR ...

.. _mod-geoip_id:

id
..

A module identifier.

.. _mod-geoip_config-file:

conf-file
.........

Full path to the response configuration file as described above.

*Required*

.. _mod-geoip_ttl:

ttl
...

The time to live of Resource Records returned by the module.

*Default:* 60

.. _mod-geoip_mode:

mode
....

The mode of operation of the module. When set to **subnet**, responses
are tailored according to subnets. When set to **geodb**, responses
are tailored according to geographic data retrieved from the configured
database.

.. _mod-geoip_geodb-file:

geodb-file
..........

Full path to a .mmdb file containing the GeoIP database.

*Reqired if* **mode** *is set to* **geodb**

.. _mod-geoip_geodb-key:

geodb-key
.........

Multi-valued item, can be specified up to **8** times. Each **geodb-key** specifies
a path to a key in a node in the supplied GeoIP database. The module currently supports
two types of values: **string** or **32-bit unsigned int**. In the latter
case, the key has to be prefixed with **(id)**. Common choices of keys include:

* **continent/code**

* **country/iso_code**

* **(id)country/geoname_id**

* **city/names/en**

* **(id)city/geoname_id**

* **isp**

* ...

In the zone's config file for the module the values of the keys are entered in the same order
as the keys in the module's configuration, separated by a semicolon. Enter the value **"*"**
if the key is allowed to have any value.
