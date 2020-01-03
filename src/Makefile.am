AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
	-DRUN_DIR='"${run_dir}"'		\
	-DMODULE_DIR='"${module_dir}"'		\
	-DMODULE_INSTDIR='"${module_instdir}"'

EXTRA_DIST =
CLEANFILES =
BUILT_SOURCES =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
pkgconfig_DATA =

include $(srcdir)/contrib/Makefile.inc
include $(srcdir)/libdnssec/Makefile.inc
include $(srcdir)/libknot/Makefile.inc
include $(srcdir)/libzscanner/Makefile.inc
include $(srcdir)/knot/Makefile.inc
include $(srcdir)/utils/Makefile.inc
