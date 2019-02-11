.. _mod-cookies:

``cookies`` — DNS Cookies
=========================

DNS Cookies (:rfc:`7873`) is a lightweight security mechanism against
denial-of-service and amplification attacks. The server keeps a secret value
(the Server Secret), which is used to generate a cookie, which is sent to
the client in the OPT RR. The server then verifies the authenticity of the client
by the presence of a correct cookie. Both the server and the client have to
support DNS Cookies, otherwise they are not used.

.. NOTE::
   This module introduces a statistics counter: the number of queries
   containing the COOKIE option.

.. WARNING::
   For effective module operation the :ref:`RRL<mod-rrl>` module must also
   be enabled.

Example
-------

It is recommended to enable DNS Cookies globally, not per zone. The module may be used without any further configuration.

::

    template:
        - id: default
          global-module: mod-cookies # Enable DNS Cookies globally

Module configuration may be supplied if necessary.

::

    mod-cookies:
      - id: default
        secret-lifetime: 30h # The Server Secret is regenerated every 30 hours
        badcookie-slip: 3    # The server replies only to every third query with a wrong cookie

    template:
      - id: default
        global-module: mod-cookies/default # Enable DNS Cookies globally

The value of the Server Secret may also be managed manually using the :ref:`mod-cookies_secret` option. In this case
the server does not automatically regenerate the Server Secret.

::

    mod-cookies:
        - id: default
          secret: 0xdeadbeefdeadbeefdeadbeefdeadbeef

Module reference
----------------

::

    mod-cookies:
      - id: STR
        secret-lifetime: TIME
        badcookie-slip: INT
        secret: STR|HEXSTR

.. _mod-cookies_id:

id
..

A module identifier.

.. _mod-cookies_secret-lifetime:

secret-lifetime
...............

This option configures how often the Server Secret is regenerated.
The maximum allowed value is 36 days (:rfc:`7873#section-7.1`).

*Default:* 26 hours

.. _mod-cookies_badcookie-slip:

badcookie-slip
..............

This option configures how often the server responds to queries containing
an invalid cookie by sending them the correct cookie.

- The value **1** means that the server responds to every query.
- The value **2** means that the server responds to every second query with
  an invalid cookie, the rest of the queries is dropped.
- The value **N > 2** means that the server responds to every N\ :sup:`th`
  query with an invalid cookie, the rest of the queries is dropped.

*Default:* 1

.. _mod-cookies_secret:

secret
......

Use this option to set the Server Secret manually. If this option is used, the
Server Secret remains the same until changed manually and the :ref:`mod-cookies_secret-lifetime` option is ignored.
The size of the Server Secret currently MUST BE 128 bits, or 32 hexadecimal characters.

*Default:* not set
