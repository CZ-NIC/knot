.. _mod-noudp:

``noudp`` — No UDP response
===========================

The module sends empty truncated response to any UDP query. TCP queries are
not affected.

Example
-------

To enable this module globally, you need to add something like the following
to the configuration file::

    template:
      - id: default
        global-module: mod-noudp

.. NOTE::
   This module is not configurable.
