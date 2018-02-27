Requirements
------------

- ansible
- vagrant
- libvirt (+vagrant-libvirt) / virtualbox

Usage
-----

`vagrant up` command is configured to trigger ansible provisioning
which configures OBS repository, installs the knot package, creates
a zone and config file, starts the knot.service and attempts to
resolve the entry from created zone file.

By default, the *knot-dns-latest* repo is used. To test the
*knot-dns-devel* repo, enable in it `knot-dns-test.yaml`.

Run the following command for every distro (aka directory with
Vagrantfile):

./test-distro.sh debian9

Caveats
-------

This tests the latest `knot` package that is available. In certain cases, this
may result in unexpected behaviour, because it might be testing a different
package than expected.

