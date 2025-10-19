lib_LTLIBRARIES += libknot.la
pkgconfig_DATA  += libknot.pc

libknot_la_CPPFLAGS = $(embedded_libngtcp2_CFLAGS) \
                      $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(lmdb_CFLAGS) \
                      $(gnutls_CFLAGS) ${fuzzer_CFLAGS}
libknot_la_LDFLAGS  = $(AM_LDFLAGS) $(libknot_VERSION_INFO) $(LDFLAG_EXCLUDE_LIBS) \
                      ${fuzzer_LDFLAGS}
libknot_la_LIBADD   = $(libcontrib_LIBS) $(lmdb_LIBS) $(gnutls_LIBS) $(math_LIBS)

if EMBEDDED_LIBNGTCP2
libknot_la_LIBADD  += $(libembngtcp2_LIBS)
endif EMBEDDED_LIBNGTCP2

if ENABLE_PKCS11
libknot_la_LIBADD  += $(pthread_LIBS)
endif

EXTRA_DIST += \
	libknot/dnssec/sample_keys.h

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
	libknot/dnssec/binary.h			\
	libknot/dnssec/crypto.h			\
	libknot/dnssec/digest.h			\
	libknot/dnssec/dnssec.h			\
	libknot/dnssec/error.h			\
	libknot/dnssec/key.h			\
	libknot/dnssec/keyid.h			\
	libknot/dnssec/keystore.h		\
	libknot/dnssec/keytag.h			\
	libknot/dnssec/nsec.h			\
	libknot/dnssec/pem.h			\
	libknot/dnssec/random.h			\
	libknot/dnssec/sign.h			\
	libknot/dnssec/tsig.h			\
	libknot/packet/compr.h			\
	libknot/packet/pkt.h			\
	libknot/packet/rrset-wire.h		\
	libknot/packet/wire.h			\
	libknot/probe/data.h			\
	libknot/probe/probe.h			\
	libknot/quic/tls.h			\
	libknot/quic/tls_common.h		\
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
	libknot/xdp/tcp_iobuf.h			\
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
	libknot/dnssec/binary.c			\
	libknot/dnssec/crypto.c			\
	libknot/dnssec/digest.c			\
	libknot/dnssec/error.c			\
	libknot/dnssec/key/algorithm.c		\
	libknot/dnssec/key/algorithm.h		\
	libknot/dnssec/key/convert.c		\
	libknot/dnssec/key/convert.h		\
	libknot/dnssec/key/dnskey.c		\
	libknot/dnssec/key/dnskey.h		\
	libknot/dnssec/key/ds.c			\
	libknot/dnssec/key/internal.h		\
	libknot/dnssec/key/key.c		\
	libknot/dnssec/key/keytag.c		\
	libknot/dnssec/key/privkey.c		\
	libknot/dnssec/key/privkey.h		\
	libknot/dnssec/key/simple.c		\
	libknot/dnssec/keyid.c			\
	libknot/dnssec/keystore/internal.h	\
	libknot/dnssec/keystore/keystore.c	\
	libknot/dnssec/keystore/pkcs11.c	\
	libknot/dnssec/keystore/pkcs8.c		\
	libknot/dnssec/nsec/bitmap.c		\
	libknot/dnssec/nsec/hash.c		\
	libknot/dnssec/nsec/nsec.c		\
	libknot/dnssec/p11/p11.c		\
	libknot/dnssec/p11/p11.h		\
	libknot/dnssec/pem.c			\
	libknot/dnssec/random.c			\
	libknot/dnssec/shared/bignum.c		\
	libknot/dnssec/shared/bignum.h		\
	libknot/dnssec/shared/binary_wire.h	\
	libknot/dnssec/shared/keyid_gnutls.c	\
	libknot/dnssec/shared/keyid_gnutls.h	\
	libknot/dnssec/shared/shared.h		\
	libknot/dnssec/sign/der.c		\
	libknot/dnssec/sign/der.h		\
	libknot/dnssec/sign/sign.c		\
	libknot/dnssec/tsig.c			\
	libknot/packet/pkt.c			\
	libknot/packet/rrset-wire.c		\
	libknot/probe/data.c			\
	libknot/probe/probe.c			\
	libknot/quic/tls.c			\
	libknot/quic/tls_common.c		\
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
	libknot/yparser/yptrafo.c		\
	libknot/xdp/tcp_iobuf.c

if ENABLE_XDP
libknot_la_CPPFLAGS += $(libbpf_CFLAGS)
libknot_la_LIBADD   += $(libbpf_LIBS)

nobase_include_libknot_HEADERS += \
	libknot/xdp/bpf-consts.h		\
	libknot/xdp/eth.h			\
	libknot/xdp/msg.h			\
	libknot/xdp/tcp.h			\
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
	libknot/xdp/xdp.c

endif ENABLE_XDP
if ENABLE_QUIC

libknot_la_CPPFLAGS += $(libngtcp2_CFLAGS) $(gnutls_CFLAGS)
libknot_la_LIBADD   += $(libngtcp2_LIBS) $(gnutls_LIBS)

nobase_include_libknot_HEADERS += \
	libknot/quic/quic.h			\
	libknot/quic/quic_conn.h

libknot_la_SOURCES  += \
	libknot/quic/quic.c			\
	libknot/quic/quic_conn.c

endif ENABLE_QUIC

DIST_SUBDIRS = libknot/xdp
