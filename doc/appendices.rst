.. highlight:: none
.. _Appendices:

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
   * - `Feitian ePass 2003 <https://www.ftsafe.com/Products/PKI/Standard>`_
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
   * - `SoftHSM 2.0 <https://www.opendnssec.org/softhsm/>`_ [#fn-softhsm]_
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
   * - `Trustway Proteccio NetHSM <https://atos.net/en/solutions/cyber-security/data-protection-and-governance/hardware-security-module-trustway-proteccio-nethsm>`_
     - |yes|
     - ECDSA only
     - |no|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
   * - `Ultra Electronics CIS Keyper Plus (Model 9860-2) <https://www.ultra.group/our-business-units/intelligence-communications/cyber/key-management/#acc-keyperplus>`_
     - |yes|
     - RSA only
     - |no|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
     - |yes|
   * - `Utimaco SecurityServer (V4) <https://hsm.utimaco.com/products-hardware-security-modules/general-purpose-hsm/securityserver-cse/>`_ [#fn-utimaco]_
     - |yes|
     - |yes|
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

.. [#fn-softhsm] Algorithms supported depend on support in OpenSSL on which SoftHSM relies.
   A command similar to the following may be used to verify what algorithms are supported:
   ``$ pkcs11-tool --modul /usr/lib64/pkcs11/libsofthsm2.so -M``.
.. [#fn-utimaco] Requires setting the number of background workers to 1!

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
