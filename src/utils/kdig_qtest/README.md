# qtest
qtest is an DoQ server implementation testing tool based on kdig.
It uses function pointers instead of normal kdig function calls to some
functions relevant to DoQ testing. This allows the user and developer to write
an altered function implementation and run the kdig resolution with this
altered code in order to test some DoQ server implementation.

# WARNING
*THIS IS A TOOL FOR LOCAL TESTING ONLY.*
Some test cases may corrupt server state, **Only use this tool on DNS servers
you own, manage, or have explicit written permission to test.** Using this
tool against public DNS servers or any infrastructure without authorization may
result in legal repercussions.

See qtest_main.c for all the test cases.
See `qtest --help` for options

`-m` option also runs manual tests, these tests require human analysis on the
server side and their success only **suggests** a successful execution of the
test, not the result itself. These tests are intended to help a server
implementation make sure the connection and server itself remain in a correct
state after a malicious or unexpected performed by the client.

# Adding more tests
## Disclaimer
qtest is a tool intended for use by developers. qtest's design offers a
straightforward way to design new DoQ tests, but this claim expects the user
to be an experienced developer.

## Lets add a test
As mentioned before the design of qtest is based around function pointers.
These are selected functions that are relevant to DoQ behaviour, we test
by changing the default kdig DoQ implementation with our modified code.
This allows us to explore the server behaviour under unexpected, malicious
and erroneous situations, verifying the server implementation handles
these correctly according to the RCF 9250 specification. Not all situations
are described in RFC 9250, but the result of any test should not cause
the server to crash. Such a result is considered a vulnerability since
potentially any user can maliciously or accidentally use this to attack the
server.

All the function calls that were replaced by function pointer calls can be
viewed at the top of qtest_main.c. These pointers are stored in `net->cbs`.
The interface for these function pointers is defined in qtest_quic.h
Additionally qtest uses the `net->quic.env` which contains free to use fields.

To design a new test we simply replace the function pointers to the functions
that we want to exhibit altered behaviour. As an example lets look at
`stream_data_split_to_two_pkts`. This test replaces the `quic_send_dns_query`
function pointer with `quic_send_dns_query_split` and `quic_send_data function`
pointer with `quic_send_data_split`. After that the test assigns an integer
value to `env->counter`, used in the previously mentioned modified functions as
the number that determines how many slices of the payload should be created and
subsequently sent in separate packets. After setting all the necessary values
we call `process_query` with the expected return value used as the test
assertion, here we only test for a successful resolution. More assertions can
be seen in other tests like send_non_zero_msgid, where the returned
DoQ Error code is checked.

Having designed a new test and implemented the altered functions we append the
unit test to one of the `struct c_m_unit_test` unit test suites in the `main`
function in qtest_main.c and run the program.

# Compilation
To build qtest two flags have to be enabled in the initial Knot-dns configure
`--enable-quic=yes|embedded` and
`--enable-qtest=yes`
the resulting binary is named qtest and can be found alongside kdig and other
utility programs in path/to/build/bin/
