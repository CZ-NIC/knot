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

.. |yes|     replace:: **yes**
.. |no|      replace:: no
.. |unknown| replace:: ?

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * -
     - Key generate
     - Key import
     - ED25519 256-bit
     - ECDSA 256-bit
     - ECDSA 384-bit
     - RSA 1024-bit
     - RSA 2048-bit
     - RSA 4096-bit
   * - `Feitian ePass 2003 <https://www.ftsafe.com/product/epass/epass2003>`_
     - |yes|
     - |no|
     - |no|
     - |no|
     - |no|
     - |yes|
     - |yes|
     - |no|
   * - `SafeNet Network HSM (Luna SA 4) <https://safenet.gemalto.com/data-encryption/hardware-security-modules-hsms/luna-hsms-key-management/luna-sa-network-hsm/>`_
     - |yes|
     - |no|
     - |no|
     - |no|
     - |no|
     - |yes|
     - |yes|
     - |yes|
   * - `SoftHSM 2.0 <https://www.opendnssec.org/softhsm/>`_
     - |yes|
     - |yes|
     - |no|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
   * - `Trustway Proteccio NetHSM <http://www.bull.com/fr/cybers%C3%A9curit%C3%A9-trustway-proteccio-nethsm>`_
     - |yes|
     - ECDSA only
     - |no|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
   * - `Utimaco SecurityServer (V4) <https://hsm.utimaco.com/products-hardware-security-modules/general-purpose-hsm/securityserver-cse/>`_
     - |yes|
     - |unknown|
     - |no|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|

.. in progress: key ID checks have to be disabled in code
   * - `Yubikey NEO <https://www.yubico.com/products/yubikey-hardware/yubikey-neo/>`_
     - |no|
     - |no|
     - |no|
     - |yes|
     - |no|
     - |yes|
     - |yes|
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
   * - ED25519
     - 15
     - 3.6.0 or newer
   * - ECDSA
     - 13, 14
     - 3.4.8 or newer
   * - RSA
     - 5, 7, 8, 10
     - 3.4.6 or newer
