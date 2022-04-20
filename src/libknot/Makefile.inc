lib_LTLIBRARIES += libknot.la
pkgconfig_DATA  += libknot.pc

libknot_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(lmdb_CFLAGS) \
                      ${fuzzer_CFLAGS}
libknot_la_LDFLAGS  = $(AM_LDFLAGS) $(libknot_VERSION_INFO) $(LDFLAG_EXCLUDE_LIBS) \
                      ${fuzzer_LDFLAGS}
libknot_la_LIBADD   = libdnssec.la $(libcontrib_LIBS) $(lmdb_LIBS) $(math_LIBS)

if EMBEDDED_LIBNGTCP2
libknot_la_LIBADD += $(libembngtcp2_LIBS)
endif EMBEDDED_LIBNGTCP2

include_libknotdir = $(includedir)
nobase_include_libknot_HEADERS = \
	libknot/attribute.h			\
	libknot/codes.h				\
	libknot/consts.h			\
	libknot/control/control.h		\
	libknot/cookies.h			\
	libknot/descriptor.h			\
	libknot/dname.h				\
	libknot/dynarray.h			\
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
	libknot/probe/data.h			\
	libknot/probe/probe.h			\
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
	libknot/rrtype/svcb.h			\
	libknot/rrtype/tsig.h			\
	libknot/rrtype/zonemd.h			\
	libknot/tsig-op.h			\
	libknot/tsig.h				\
	libknot/wire.h				\
	libknot/yparser/yparser.h		\
	libknot/yparser/ypformat.h		\
	libknot/yparser/ypschema.h		\
	libknot/yparser/yptrafo.h		\
	libknot/version.h			\
	libknot/xdp.h

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
	libknot/probe/data.c			\
	libknot/probe/probe.c			\
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

if EMBEDDED_LIBBPF
libknot_la_LIBADD   += $(libembbpf_LIBS)
endif EMBEDDED_LIBBPF
if ENABLE_XDP
libknot_la_CPPFLAGS += $(libbpf_CFLAGS)
libknot_la_LIBADD   += $(libbpf_LIBS)

nobase_include_libknot_HEADERS += \
	libknot/xdp/bpf-consts.h		\
	libknot/xdp/eth.h			\
	libknot/xdp/msg.h			\
	libknot/xdp/tcp.h			\
	libknot/xdp/tcp_iobuf.h			\
	libknot/xdp/xdp.h

libknot_la_SOURCES  += \
	libknot/xdp/bpf-kernel-obj.c		\
	libknot/xdp/bpf-kernel-obj.h		\
	libknot/xdp/bpf-user.c			\
	libknot/xdp/bpf-user.h			\
	libknot/xdp/eth.c			\
	libknot/xdp/msg_init.h			\
	libknot/xdp/protocols.h			\
	libknot/xdp/tcp.c			\
	libknot/xdp/tcp_iobuf.c			\
	libknot/xdp/xdp.c

if ENABLE_XDP_QUIC

libknot_la_CPPFLAGS += $(libngtcp2_CFLAGS)
libknot_la_LIBADD   += $(libngtcp2_LIBS)

nobase_include_libknot_HEADERS += \
        libknot/xdp/quic.h                      \
        libknot/xdp/quic_conn.h

libknot_la_SOURCES  += \
	libknot/xdp/quic.c                      \
        libknot/xdp/quic_conn.c

endif ENABLE_XDP_QUIC
endif ENABLE_XDP

DIST_SUBDIRS = libknot/xdp
