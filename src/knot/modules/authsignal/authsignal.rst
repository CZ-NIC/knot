.. _mod-authsignal:

``authsignal`` – Automatic Authenticated DNSSEC Bootstrapping records
=====================================================================

This module is able to synthesize records for automatic DNSSEC bootstrapping
(draft-ietf-dnsop-dnssec-bootstrapping).

Records are synthesized only if the query can't be satisfied from the zone.

Synthesized records also need to be signed. Typically, this would be done
using the :ref:`onlinesign<mod-onlinesign>` module.

Example
-------

Automatic forward records
.........................

::
   mod-onlinesign:
     - id: authsignal
       nsec-bitmap: [CDS, CDNSKEY]

   zone:
     - domain: example.net
       dnssec-signing: on
     - domain: _signal.ns1.example.com
       module: [mod-authsignal, mod-onlinesign/authsignal]

Result:

.. code-block:: console

   $ kdig CDS _dsboot.example.net._signal.ns1.example.com.
   ...
   ;; QUESTION SECTION:
   ;; _dsboot.example.net._signal.ns1.example.com. 	IN	CDS

   ;; ANSWER SECTION:
   _dsboot.example.net._signal.ns1.example.com. 0	IN	CDS	45504 13 2 2F2D518FD9DBB2B1403F51398A9931F2832B89F0F85C146B130D383FC23584FA
