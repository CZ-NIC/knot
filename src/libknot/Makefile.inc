lib_LTLIBRARIES += libknot.la
pkgconfig_DATA  += libknot.pc

libknot_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(lmdb_CFLAGS)
libknot_la_LDFLAGS  = $(AM_LDFLAGS) $(libknot_VERSION_INFO) $(LDFLAG_EXCLUDE_LIBS)
libknot_la_LIBADD   = libcontrib.la libdnssec.la $(math_LIBS) $(lmdb_LIBS)

include_libknotdir = $(includedir)
nobase_include_libknot_HEADERS = \
	libknot/attribute.h			\
	libknot/codes.h				\
	libknot/consts.h			\
	libknot/control/control.h		\
	libknot/cookies.h			\
	libknot/descriptor.h			\
	libknot/dname.h				\
	libknot/endian.h			\
	libknot/errcode.h			\
	libknot/error.h				\
	libknot/libknot.h			\
	libknot/lookup.h			\
	libknot/mm_ctx.h			\
	libknot/db/db.h				\
	libknot/db/db_lmdb.h			\
	libknot/db/db_trie.h			\
	libknot/packet/compr.h			\
	libknot/packet/pkt.h			\
	libknot/packet/rrset-wire.h		\
	libknot/packet/wire.h			\
	libknot/rdata.h				\
	libknot/rdataset.h			\
	libknot/rrset-dump.h			\
	libknot/rrset.h				\
	libknot/rrtype/dnskey.h			\
	libknot/rrtype/ds.h			\
	libknot/rrtype/naptr.h			\
	libknot/rrtype/nsec.h			\
	libknot/rrtype/nsec3.h			\
	libknot/rrtype/nsec3param.h		\
	libknot/rrtype/opt.h			\
	libknot/rrtype/rdname.h			\
	libknot/rrtype/rrsig.h			\
	libknot/rrtype/soa.h			\
	libknot/rrtype/tsig.h			\
	libknot/tsig-op.h			\
	libknot/tsig.h				\
	libknot/wire.h				\
	libknot/yparser/yparser.h		\
	libknot/yparser/ypformat.h		\
	libknot/yparser/ypschema.h		\
	libknot/yparser/yptrafo.h		\
	libknot/version.h

libknot_la_SOURCES = \
	libknot/codes.c				\
	libknot/control/control.c		\
	libknot/cookies.c			\
	libknot/descriptor.c			\
	libknot/dname.c				\
	libknot/error.c				\
	libknot/db/db_lmdb.c			\
	libknot/db/db_trie.c			\
	libknot/packet/pkt.c			\
	libknot/packet/rrset-wire.c		\
	libknot/rdataset.c			\
	libknot/rrset-dump.c			\
	libknot/rrset.c				\
	libknot/rrtype/naptr.c			\
	libknot/rrtype/opt.c			\
	libknot/rrtype/tsig.c			\
	libknot/tsig-op.c			\
	libknot/tsig.c				\
	libknot/yparser/yparser.c		\
	libknot/yparser/ypbody.c		\
	libknot/yparser/ypformat.c		\
	libknot/yparser/ypschema.c		\
	libknot/yparser/yptrafo.c
