**********************
Knot DNS Configuration
**********************

In this chapter we provide suggested configurations and explain the
meaning of individual configuration options.

Minimal configuration
=====================

The following configuration presents a minimal configuration file
which can be used as a base for your Knot DNS setup::

    # This is a sample of a minimal configuration file for Knot DNS.
    #
    # For exhaustive list of all options see samples/knot.full.conf
    # in the source directory.
    #

    interfaces {
        my_interface { address 127.0.0.1@53; }
        second_int { address ::1; }
    }

    log {
      syslog { any notice, warning, error; }
    }

    zones {
      example.com {
        file "/etc/knot/example.com";
      }
    }

Now let's go step by step through this minimal configuration file:

* The ``interfaces`` statement defines interfaces where Knot
  DNS will listen for incoming connections. We have defined two
  interfaces: one IPv4 called ``my_interface`` explicitly listening
  on port 53 and second IPv6 called ``second_int`` also listening on
  port 53, which is the default port for the DNS. See :ref:`interfaces`.
* The ``log`` statement defines the log facilities for Knot DNS.
  In this example we told Knot DNS to send its log messages with the severities
  ``debug``, ``warning`` and ``notice`` into the syslog.
  If you omit this sections, all severities will printed to
  either ``stdout`` or ``stderr``, and the severities
  from the ``warning`` and more serious to syslog. You can find all
  possible combinations in the :ref:`log`.
* The ``zones`` statement is probably the most important one,
  because it defines the zones that Knot DNS will serve.  In its most simple
  form you can define a zone by its name and zone file.

Slave configuration
===================

Knot DNS doesn't strictly differ between master and slave zones.  The
only requirement is to have ``xfr-in`` ``zones`` statement set for
given zone, thus allowing both incoming XFR from that remote and using
it as the zone master. If ``update-in`` is set and zone has a master,
any accepted DNS UPDATE will be forwarded to master.  Also note that
you need to explicitly allow incoming NOTIFY, otherwise the daemon
would reject them.  Also, you can specify paths, relative to the
storage directory.  See :ref:`zones` and :ref:`storage`.  If the zone
file doesn't exist and ``xfr-in`` is set, it will be bootstrapped over
AXFR::

    remotes {
      master { address 127.0.0.1@53; }
      subnet1 { address 192.168.1.0/24; }
    }

    zones {
      example.com {
        file "example.com"; # relative to 'storage'
        xfr-in master;      # define 'master' for this zone
        notify-in master;   # also allow NOTIFY from 'master'
        update-in subnet1;  # accept UPDATE msgs from subnet1 and forward
                            # to master
      }
    }

You can also use TSIG for access control. For this, you need to configure a TSIG key
and assign it to a remote.  Supported algorithms for TSIG key are:
| ``hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512``
Key secret is written in a base64 encoded format. See :ref:`keys`::

    keys {
      key0 hmac-md5 "Wg=="; # keyname algorithm secret
    }
    remotes {
      master { address 127.0.0.1@53; key key0; }
    }
    zones {
      example.com {
        file "example.com"; # relative to 'storage'
        xfr-in master;      # define 'master' for this zone
        notify-in master;   # also allow NOTIFY from 'master'
      }
    }

As of now it is not possible to associate multiple keys with a remote.

Master configuration
====================

You can specify which remotes to allow for outgoing XFR and NOTIFY ``zones``::

    remotes {
      slave { address 127.0.0.1@53; }
      any { address 0.0.0.0/0; }
      subnet1 { address 192.168.1.0/8; }
      subnet2 { address 192.168.2.0/8; }
    }
    zones {
      example.com {
        file "/var/zones/example.com";
        xfr-out subnet1, subnet2; # allow outgoing transfers
        notify-out slave;
        update-in subnet1; # only allow DNS UPDATE from subnet1
      }
    }

You can also secure outgoing XFRs with TSIG::

    keys {
      key0 hmac-md5 "Wg=="; # keyname algorithm secret
    }
    remotes {
      any { address 0.0.0.0/0; key key0; }
    }
    zones {
      example.com {
        file "/var/zones/example.com";
        xfr-out any; # uses 'any' remote secured with TSIG key 'key0'
      }
    }

Configuring multiple interfaces
===============================

Knot DNS support binding to multiple available interfaces in the
``interfaces`` section.  You can also use the special addresses for
"any address" like ``0.0.0.0`` or ``[::]``::

    interfaces {
      if1 { address 192.168.1.2@53; }
      anyv6 { address [::]@53; }
    }

Using DNS UPDATE
================

As noted in examples for master and slave, it is possible to accept
DNS UPDATE messages.  When the zone is configured as a slave and DNS
UPDATE messages is accepted, server forwards the message to its
primary master specified by ``xfr-in`` directive. When it receives the
response from primary master, it forwards it back to the
originator. This finishes the transaction.

However, if the zone is configured as master (i.e. not having any
``xfr-in`` directive), it accepts such an UPDATE and processes it.

Remote control interface
========================

As of v1.3.0, it is possible to control running daemon using UNIX
sockets, which is also preferred over internet sockets. You don't need
any specific configuration, since it is enabled by default and the
UNIX socket is placed in the rundir.  To disable remote control
completely, add an empty ``control`` section to the configuration
like::

    control { }

However you can still use IPv4/IPv6 address, although with several
shortcomings.  You then can use ``allow`` for an ACL list similar to
``xfr-in`` or ``xfr-out``, see that for syntax reference. The
``listen-on`` has syntax equal to an interface specification, but the
default port for remote control protocol is ``5533``.  However keep in
mind, that the transferred data isn't encrypted and could be
susceptible to replay attack in a short timeframe.

Example configuration::

    control {
    	listen-on { address 127.0.0.1@5533; }
    }

Enabling zone semantic checks
=============================

You can turn on more detailed semantic checks of zone file in this
``zones`` statement :ref:`zones`. Refer to :ref:`zones List of zone
semantic checks` to see which checks are enabled by default and which
are optional.

Creating IXFR differences from zone file changes
================================================

If Knot is being run as a master server, feature
``ixfr-from-differences`` can be enabled to create IXFR differences
from changes made to the master zone file.  See :ref:`Controlling
running daemon` for more information. For more about ``zones``
statement see :ref:`zones`.

Using Response Rate Limiting
============================

Response rate limiting (RRL) is a method to combat recent DNS
reflection amplification attacks.  These attacked rely on the fact
that source address of a UDP query could be forged, and without a
worldwide deployment of BCP38, such a forgery could not be detected.
Attacker could then exploit DNS server responding to every query,
potentially flooding the victim with a large unsolicited DNS
responses.

As of Knot DNS version 1.2.0, RRL is compiled in, but disabled by
default.  You can enable it with the :ref:`rate-limit` option in the
:ref:`system` section.  Setting to a value greater than ``0`` means
that every flow is allowed N responses per second, (i.e. ``rate-limit
50;`` means ``50`` responses per second).  It is also possible to
configure SLIP interval, which causes every Nth blocked response to be
slipped as a truncated response. Not that some error responses cannot
be truncated and are slipped as-is.  For more information, refer to
:ref:`rate-limit-slip`.  It is advisable to not set slip interval to a
value larger than 1.

Example configuration::

    system {
    	rate-limit 200;    # Each flow is allowed to 200 resp. per second
    	rate-limit-slip 1; # Every response is slipped (default)
    }

Automatic DNSSEC signing
========================

Knot DNS 1.4.0 is the first release to include automatic DNSSEC
signing feature.  Automatic DNSSEC signing is currently a technical
preview and there are some limitations we will try to eliminate. The
concept of key management and configuration is likely to change in the
future without maintaining backward compatibility.

Example configuration
---------------------

The example configuration enables automatic signing for all zones
using :ref:`dnssec-enable` option in the ``zones`` section, but the
signing is explicitly disabled for zone ``example.dev`` using the same
option directly in zone configuration. The location of directory with
signing keys is set globally by option :ref:`dnssec-keydir`::

    zones {
      dnssec-enable on;
      dnssec-keydir "/var/lib/knot/keys";

      example.com {
        file "example.com.zone";
      }

      example.dev {
        file "example.dev.zone";
        dnssec-enable off;
      }
    }

Signing keys
------------

The signing keys can be generated using ISC ``dnssec-keygen`` tool
only and there are some limitations:

* Keys for all zones must be placed in one directory.
* Algorithms based on RSA, DSA, and ECDSA are supported, support for
  GOST algorithm is not finished yet.
* Only key publication, activation, inactivation, and removal time
  stamps are utilized. Other time stamps are ignored.
* It is required, that both ``.private`` and ``.key`` files for each
  key are available in the key directory in order to use the keys
  (even for verification only).
* There cannot be more than eight keys per zone. Keys which are not
  published are not included in this number.

Example how to generate NSEC3 capable zone signing key (ZSK) and key
signing key (KSK) for zone ``example.com``::

    $ cd /var/lib/knot/keys
    $ dnssec-keygen -3 example.com
    $ dnssec-keygen -3 -f KSK example.com

Signing policy
--------------

Currently the signing policy is not configurable, except for signature
lifetime.

* Signature lifetime can be set in configuration globally for all
  zones and for each zone in particular. :ref:`signature-lifetime`. If
  not set, the default value is 30 days.
* Signature is refreshed 2 hours before expiration. The signature
  lifetime must thus be set to more than 2 hours.

Zone signing
------------

The signing process consists of the following steps:

* Fixing ``NSEC`` or ``NSEC3`` records. This is determined by
  ``NSEC3PARAM`` record presence in unsigned zone.
* Updating ``DNSKEY`` records. This also means adding DNSKEY records
  for any keys that are present in keydir, but missing in zone file.
* Removing expired signatures, invalid signatures, signatures expiring
  in a short time, and signatures with unknown key.
* Creating any missing signatures. ``DNSKEY`` records are signed by
  both ZSK and KSK keys, other records are signed only by ZSK keys.
* SOA record is updated and resigned if any changes were performed.

The zone signing is performed when the zone is loaded into server, on
zone reload, before any signature is expiring, and after DDNS
update. The signing can be also forced using ``signzone`` command
issued by ``knotc``, in this case all signatures are recreated. After
each zone signing, a new signing event is planned. User can view the
time of this event by using the ``knotc zonestatus`` command.

Query modules
=============

Knot DNS supports configurable query modules that can alter the way
queries are processed.  The concept is quite simple - each query
requires a finite number of steps to be resolved.  We call this set of
steps a query plan, an abstraction that groups these steps into
several stages.

* Before query processing
* Answer, Authority, Additional records packet sections processing
* After query processing

For example, processing an Internet zone query needs to find an
answer. Then based on the previous state, it may also append an
authority SOA or provide additional records.  Each of these actions
represents a 'processing step'.  Now if a query module is loaded for a
zone, it is provided with an implicit query plan, and it is allowed to
extend it or even change it altogether.

*Note:* Programmable interface is described in the ``query_module.h``,
it will not be discussed here.

The general syntax for importing a query module is described in the
:ref:`query_module` configuration reference.  Basically, each module is
described by a name and a configuration string.  Below is a list of
modules and configuration string reference.

``dnstap`` - dnstap-enabled query logging
-----------------------------------------

The Knot DNS supports dnstap_ for query and response logging.
You can capture either either all or zone-specific queries and responses, usually you want to do
the former. The dnstap module accepts only a sink path as a parameter, which can either be a file
or a UNIX socket prefixed with *unix:*.

For example::

    zones {
        query_module "/tmp/capture.tap";
    }

You can also log to a UNIX socket with the prefix::

    zones {
        query_module "unix:/tmp/capture.tap";
    }

.. _dnstap: http://dnstap.info/

``synth_record`` - Automatic forward/reverse records
----------------------------------------------------

This module is able to synthetise either forward or reverse records for given prefix and subnet.
The module configuration string looks like this: ``(forward|reverse) <prefix> <ttl> <address>/<netblock>``.

Records are synthetised only if the query can't be satisfied from the zone. Both IPv4 and IPv6 are supported.
*Note: 'prefix' doesn't allow dots, address parts in the synthetic names are separated with a dash.*

Here are a few examples:
*Note: long names are snipped for readability.*

Automatic forward records
-------------------------

``synth_record "forward dynamic- 400 2620:0:b61::/52"`` on ``example.`` zone will result in following
answer::

    $ kdig AAAA dynamic-2620-0000-0b61-0100-0000-0000-0000-0000.example.
    ...
    ;; QUESTION SECTION:
    ;; dynamic-2620-0000-0b61-0100-0000-0000-0000-0000.example. 0	IN	AAAA

    ;; ANSWER SECTION:
    dynamic-2620-0000-0b61-0100... 400 IN AAAA 2620:0:b61:100::

You can also have CNAME aliases to the dynamic records, which are going to be further resoluted::

    $ kdig AAAA hostalias.example.
    ...
    ;; QUESTION SECTION:
    ;hostalias.example. 0	IN	AAAA

    ;; ANSWER SECTION:
    hostalias.example. 3600 IN CNAME dynamic-2620-0000-0b61-0100...
    dynamic-2620-0000-0b61-0100... 400  IN AAAA  2620:0:b61:100::

Automatic reverse records
-------------------------

Module can be configured to synthetise reverse records as well.  With
the ``synth_record "reverse dynamic- example. 400 2620:0:b61::/52"``
string in the ``1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.`` zone
configuration::

    $ kdig PTR 1.0.0...1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.
    ...
    ;; QUESTION SECTION:
    ;; 1.0.0...1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa. 0	IN	PTR

    ;; ANSWER SECTION:
    ... 400 IN PTR dynamic-2620-0000-0b61-0000-0000-0000-0000-0001.example.

Here's a full configuration of the aforementioned zones. Note that the zone files have to exist::

    example. {
      query_module {
        synth_record "forward dynamic- 400 2620:0:b61::/52";
        synth_record "forward dynamic- 400 192.168.1.0/25";
      }
    }
    1.168.192.in-addr.arpa {
      query_module {
        synth_record "reverse dynamic- example. 400 192.168.1.0/25";
      }
    }
    1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa {
      query_module {
        synth_record "reverse dynamic- example. 400 2620:0:b61::/52";
      }
    }

Limitations
^^^^^^^^^^^

* As of now, there is no authenticated denial of nonexistence (neither
  NSEC or NSEC3 is supported) nor DNSSEC signed records.  However,
  since the module is hooked in the query processing plan, it will be
  possible to do online signing in the future.
