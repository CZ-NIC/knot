# qtest utility

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

See qtest_main.c for all the test cases, this tool can also be compiled in
non-manual testing mode (currently done by switching MANUAL_TESTING macro in qtest_main.c to false)
for use in automated testing suites. This is necessary as some tests require
human analysis of the server state and their success only means a successful
execution of the test, not the result itself.
