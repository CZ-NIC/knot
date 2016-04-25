.. highlight:: none
.. _Appendicies:

**********
Appendices
**********

.. _compatible_pkcs11_devices:

Compatible PKCS #11 Devices
===========================

This section has informative character. Knot DNS has been tested with several
devices which claim to support PKCS #11 interface. The following table
indicates which algorithms and operations have been seen to work. Please notice
minimal GnuTLS library version required for particular algorithm support.

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * -
     - ECDSA [#ecdsa]_
     - RSA [#rsa]_
     - DSA [#dsa]_
     - key import
     - key generation
   * - `SoftHSM <https://www.opendnssec.org/softhsm/>`_ 2.0
     - yes
     - yes
     - yes
     - yes
     - yes
   * - `Luna SA (SafeNet Network HSM) <http://www.safenet-inc.com/data-encryption/hardware-security-modules-hsms/luna-hsms-key-management/luna-sa-network-hsm/>`_
     - **no**
     - yes
     - yes
     - yes
     - **no**
.. in progress
   * - `Trustway Proteccio NetHSM <http://www.bull.com/fr/cybers%C3%A9curit%C3%A9-trustway-proteccio-nethsm>`_
     - ?
     - ?
     - ?
     - ?
     - ?
   * - ePass 2003
     - ?
     - ?
     - ?
     - ?
     - ?
   * - Yubikey Neo
     - ?
     - ?
     - ?
     - ?
     - ?

.. [#ecdsa] DNSSEC algorithm 13. Requires GnuTLS 3.4.8 or newer.
.. [#rsa]   DNSSEC algorithms 5, 7, 8, and 10. Requires GnuTLS 3.4.6 or newer.
.. [#dsa]   DNSSEC algorithms 3 and 6. Requries GnuTLS 3.4.10 or newer.
