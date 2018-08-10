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

By default, the *knot-dns-devel* repo is used. To test the
*knot-dns-latest* or *knot-dns-testing* repo, set it in `repos.yaml`
(or use the test-distro.sh script which overwrites this file). If
you're running tests in parallel, they all HAVE TO use the same repo.

Run the following command for every distro (aka directory with
Vagrantfile):

```
./test-distro.sh devel debian9
```

or

```
./test-distro.sh testing debian9
```

or

```
./test-distro.sh latest debian9
```

At the end of the test, the package version that was tested is
printed out. Make sure you're testing what you intended to.
