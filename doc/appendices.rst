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
support. Factors like firmware and Cryptoki module version might affect the
outcome.

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * -
     - Generate
     - Import
     - EdDSA
     - ECDSA
     - RSA
     - Tested
   * - `Utimaco SecurityServer (V4) <https://utimaco.com/>`_ [#fn-utimaco]_
     - yes
     - yes
     - n/a
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2018-09
   * - `Trustway Proteccio NetHSM <https://eviden.com/en/products/cybersecurity/data-protection/hsm/proteccio-hsm>`_
     - yes
     - ECDSA only
     - n/a
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2019-03
   * - `Ultra Electronics CIS Keyper Plus (Model 9860-2) <https://www.ultra-ic.com/>`_
     - yes
     - RSA only
     - n/a
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2020-01
   * - `SoftHSM 2.0 <https://www.softhsm.org/>`_ [#fn-softhsm]_
     - yes
     - yes
     - | ed25519
       | ed448
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2025-12
   * - `Thales Luna Cloud HSM (non-FIPS) <https://thalesdocs.com/dpod/services/luna_cloud_hsm/index.html>`_
     - yes
     - n/a
     - n/a
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2025-11
   * - `Thales Luna Network HSM (non-FIPS) <https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/Home_Luna.htm>`_
     - yes
     - n/a
     - | ed448
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2025-12
   * - `Securosys Primus HSM and CloudHSM (non-FIPS) <https://docs.securosys.com/knot-dns/installation>`_
     - yes
     - yes
     - | ed25519
       | ed448
     - | 256
       | 384
     - | 1024
       | 2048
       | 4096
     - 2025-12

.. in progress: key ID checks have to be disabled in code
   * - `Yubikey NEO <https://support.yubico.com/s/article/YubiKey-NEO>`_
     - |no|
     - |no|
     - |no|
     - |yes|
     - |no|
     - |yes|
     - |yes|
     - |no|

.. [#fn-utimaco] Requires setting the number of background workers to 1!
.. [#fn-softhsm] Algorithms supported depend on support in OpenSSL on which SoftHSM relies.
   A command similar to the following may be used to verify what algorithms are supported:
   ``$ pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so -M``.
