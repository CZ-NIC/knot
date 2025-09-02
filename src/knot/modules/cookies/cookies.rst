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
   This module introduces two statistics counters:

   - ``presence`` – The number of queries containing the COOKIE option.
   - ``dropped`` – The number of dropped queries due to the slip limit.

Example
-------

It is recommended to enable DNS Cookies globally, not per zone. The module may be used without any further configuration.

::

    template:
        - id: default
          global-module: mod-cookies  # Enable DNS Cookies globally with defaults

Module configuration may be supplied if necessary.

::

    mod-cookies:
      - id: custom
        badcookie-slip: 3  # The server replies only to every third query with a wrong cookie
        secret: 0xdeadbeefdeadbeefdeadbeefdeadbeef  # Explicit Server Secret

    template:
      - id: default
        global-module: mod-cookies/custom  # Enable DNS Cookies globally with custom settings

Module reference
----------------

::

    mod-cookies:
      - id: STR
        secret-lifetime: TIME
        badcookie-slip: INT
        secret: STR | HEXSTR ...

.. _mod-cookies_id:

id
..

A module identifier.

.. _mod-cookies_secret-lifetime:

secret-lifetime
...............

This option configures in seconds how often the Server Secret is regenerated.
The maximum allowed value is 36 days (:rfc:`7873#section-7.1`).

*Default:* ``26h`` (26 hours)

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

*Default:* ``1``

.. _mod-cookies_secret:

secret
......

Use this option to set the Server Secret manually. If this option is used, the
Server Secret remains the same until changed manually and the :ref:`mod-cookies_secret-lifetime` option is ignored.
The size of the Server Secret currently MUST BE 16 bytes, or 32 hexadecimal characters.

It's possible to specify a second Server Secret, which is used for the fallback when
the cookie verification with the first Server Secret fails (secret rollover).

*Default:* not set
