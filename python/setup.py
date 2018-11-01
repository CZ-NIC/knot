from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))
with codecs.open(os.path.join(here, 'README.rst'), encoding='utf-8') as readme:
    long_description = readme.read()

setup(
    name = "libknot",
    packages = find_packages(),
    use_scm_version = {"root": "../"},
    setup_requires=["setuptools_scm"],
    description = "KnotDNS python bindings",
    long_description = long_description,
    url = "https://gitlab.labs.nic.cz/knot/knot-dns/tree/master/python/",
    author = "CZ.NIC, z.s.p.o.",
    author_email = "daniel.salzman@nic.cz",
    install_requires = [],
    keywords = ["KnotDNS"],
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration"
    ]
)
