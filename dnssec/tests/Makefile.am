AM_CPPFLAGS = -I$(top_srcdir)/libtap
LDADD = $(top_builddir)/libtap/libtap.a

check_PROGRAMS = \
	key

check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests -s $(top_srcdir)/tests \
					-b $(top_builddir)/tests \
					$(check_PROGRAMS)
