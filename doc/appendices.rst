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

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * -
     - Generate
     - Import
     - ED25519
     - ECDSA
     - RSA
     - Last tested
   * - `Feitian ePass 2003 <https://www.ftsafe.com/Products/PKI/Standard>`_
     - yes
     - n/a
     - n/a
     - n/a
     - | 1024
       | 2048
     - 2017-07
   * - `SafeNet Network HSM (Luna SA 4) <https://safenet.gemalto.com/data-encryption/hardware-security-modules-hsms/luna-hsms-key-management/luna-sa-network-hsm/>`_
     - yes
     - n/a
     - n/a
     - n/a
     - | 1024
       | 2048
       | 4096
     - 2017-07
   * - `SoftHSM 2.0 <https://www.opendnssec.org/softhsm/>`_ [#fn-softhsm]_
     - yes
     - yes
     - | 256
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2021-09
   * - `Trustway Proteccio NetHSM <https://atos.net/en/solutions/cyber-security/data-protection-and-governance/hardware-security-module-trustway-proteccio-nethsm>`_
     - yes
     - ECDSA only
     - n/a
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2019-03
   * - `Ultra Electronics CIS Keyper Plus (Model 9860-2) <https://www.ultra.group/our-business-units/intelligence-communications/cyber/key-management/#acc-keyperplus>`_
     - yes
     - RSA only
     - n/a
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2020-01
   * - `Utimaco SecurityServer (V4) <https://hsm.utimaco.com/products-hardware-security-modules/general-purpose-hsm/securityserver-cse/>`_ [#fn-utimaco]_
     - yes
     - yes
     - n/a
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2018-09

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
