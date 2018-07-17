.. _mod-geoip:

``geoip`` — Geography-based responses 
=====================================

This module offers response tailoring based on client's
subnet or geographic location. It supports GeoIP databases
in the MaxMind DB format, such as `GeoIP2 <https://dev.maxmind.com/geoip/geoip2/downloadable/>`_ 
or the free version `GeoLite2 <https://dev.maxmind.com/geoip/geoip2/geolite2/>`_.
Furthermore, the module uses EDNS Client Subnet as per :rfc:`7871` to choose 
more accurate responses. 

The module can be enabled only per zone.

Example
-------
* This is an example configuration.::

   mod-geoip:
     - id: default
       conf-file: /path/to/geo.conf
       ttl: 20
       mode: geodb
       geodb-file: /path/to/GeoLite2-City.mmdb
       geodb-key: [country/iso_code, (id)city/geoname_id]
   
   zone:
     - domain: example.com.
       module: mod-geoip/default

* The module requires an additional configuration file specifying
  the desired responses to clients querying from specific subnets::

   foo.example.com:
     - subnet: 24.121.0.0/16
       A: 24.121.1.3
     - subnet:
   ... 

  or geographic locations::

   foo.example.com:
     - geo: "US;"
       A: 1.2.3.4

Module reference
----------------

::

 mod-geoip:
   - id: STR
     conf-file: STR
     ttl: TIME
     mode: geodb | subnet
     geodb-file: STR
     geodb-key: STR ...

.. _mod-geoip_id:

id
..

A module identifier.

.. _mod-geoip_conf-file:

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

Multi-valued item, can be specified up to **8** times. 
