check_PROGRAMS = tests/runtests tests/journal
check_LIBRARIES = tests/tap/libtap.a

AM_CPPFLAGS = -I$(top_srcdir)/src \
	      -DSYSCONFDIR='"$(sysconfdir)"' -DSBINDIR='"$(sbindir)"'

tests_runtests_CPPFLAGS = \
	-DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'

tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/t
tests_tap_libtap_a_SOURCES = \
	tests/tap/basic.c tests/tap/basic.h \
	tests/tap/float.c tests/tap/float.h \
	tests/tap/macros.h

check-local: $(check_PROGRAMS)
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS

tests_journal_LDADD = \
	tests/tap/libtap.a \
	src/libknotd.la src/libknots.la \
	@LIBOBJS@
