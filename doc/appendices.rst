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
indicates which algorithms and operations have been observed to work. Please
notice minimal GnuTLS library version required for particular algorithm
support.

.. |yes| replace:: **yes**
.. |no| replace:: no
.. |unknown| replace:: ?

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * -
     - Key generate
     - Key import
     - ECDSA 256-bit
     - ECDSA 384-bit
     - RSA 1024-bit
     - RSA 2048-bit
     - RSA 4096-bit
     - DSA 512-bit
     - DSA 1024-bit
   * - `Feitian ePass 2003 <http://www.ftsafe.com/product/epass/epass2003>`_
     - |yes|
     - |no|
     - |no|
     - |no|
     - |yes|
     - |yes|
     - |no|
     - |no|
     - |no|
   * - `SafeNet Network HSM (Luna SA 4) <http://www.safenet-inc.com/data-encryption/hardware-security-modules-hsms/luna-hsms-key-management/luna-sa-network-hsm/>`_
     - |yes|
     - |no|
     - |no|
     - |no|
     - |yes|
     - |yes|
     - |yes|
     - |no|
     - |no|
   * - `SoftHSM 2.0 <https://www.opendnssec.org/softhsm/>`_
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
.. in progress
   * - `Trustway Proteccio NetHSM <http://www.bull.com/fr/cybers%C3%A9curit%C3%A9-trustway-proteccio-nethsm>`_
     - |unknown|
     - |unknown|
     - |unknown|
     - |unknown|
     - |unknown|
     - |unknown|
     - |unknown|
     - |unknown|
     - |unknown|

.. in progress: key ID checks have to be disabled in code
   * - `Yubikey NEO <https://www.yubico.com/products/yubikey-hardware/yubikey-neo/>`_
     - |no|
     - |no|
     - |yes|
     - |no|
     - |yes|
     - |yes|
     - |no|
     - |no|
     - |no|

The following table summarizes supported DNSSEC algorithm numbers and minimal
GnuTLS library version required. Any algorithm may work with older library,
however the supported operations may be limited (e.g. private key import).

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * -
     - `Numbers <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1>`_
     - GnuTLS version
   * - ECDSA
     - 13, 14
     - 3.4.8 or newer
   * - RSA
     - 5, 7, 8, 10
     - 3.4.6 or newer
   * - DSA
     - 3, 6
     - 3.4.10 or newer
