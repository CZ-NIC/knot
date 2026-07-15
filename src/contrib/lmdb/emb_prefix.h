/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

/*
 *  nm -g --defined-only libemblmdb.a \
 *    | awk '$2=="T" && $3!="mdb_dump" {printf "#define %s emb_%s\n", $3, $3}'
 */

#define mdb_cmp emb_mdb_cmp
#define mdb_cursor_close emb_mdb_cursor_close
#define mdb_cursor_count emb_mdb_cursor_count
#define mdb_cursor_dbi emb_mdb_cursor_dbi
#define mdb_cursor_del emb_mdb_cursor_del
#define mdb_cursor_get emb_mdb_cursor_get
#define mdb_cursor_open emb_mdb_cursor_open
#define mdb_cursor_put emb_mdb_cursor_put
#define mdb_cursor_renew emb_mdb_cursor_renew
#define mdb_cursor_txn emb_mdb_cursor_txn
#define mdb_dbi_close emb_mdb_dbi_close
#define mdb_dbi_flags emb_mdb_dbi_flags
#define mdb_dbi_open emb_mdb_dbi_open
#define mdb_dcmp emb_mdb_dcmp
#define mdb_del emb_mdb_del
#define mdb_drop emb_mdb_drop
#define mdb_env_close emb_mdb_env_close
#define mdb_env_copy emb_mdb_env_copy
#define mdb_env_copy2 emb_mdb_env_copy2
#define mdb_env_copyfd emb_mdb_env_copyfd
#define mdb_env_copyfd2 emb_mdb_env_copyfd2
#define mdb_env_create emb_mdb_env_create
#define mdb_env_get_fd emb_mdb_env_get_fd
#define mdb_env_get_flags emb_mdb_env_get_flags
#define mdb_env_get_maxkeysize emb_mdb_env_get_maxkeysize
#define mdb_env_get_maxreaders emb_mdb_env_get_maxreaders
#define mdb_env_get_path emb_mdb_env_get_path
#define mdb_env_get_userctx emb_mdb_env_get_userctx
#define mdb_env_info emb_mdb_env_info
#define mdb_env_open emb_mdb_env_open
#define mdb_env_set_assert emb_mdb_env_set_assert
#define mdb_env_set_flags emb_mdb_env_set_flags
#define mdb_env_set_mapsize emb_mdb_env_set_mapsize
#define mdb_env_set_maxdbs emb_mdb_env_set_maxdbs
#define mdb_env_set_maxreaders emb_mdb_env_set_maxreaders
#define mdb_env_set_userctx emb_mdb_env_set_userctx
#define mdb_env_stat emb_mdb_env_stat
#define mdb_env_sync emb_mdb_env_sync
#define mdb_get emb_mdb_get
#define mdb_put emb_mdb_put
#define mdb_reader_check emb_mdb_reader_check
#define mdb_reader_list emb_mdb_reader_list
#define mdb_set_compare emb_mdb_set_compare
#define mdb_set_dupsort emb_mdb_set_dupsort
#define mdb_set_relctx emb_mdb_set_relctx
#define mdb_set_relfunc emb_mdb_set_relfunc
#define mdb_stat emb_mdb_stat
#define mdb_strerror emb_mdb_strerror
#define mdb_txn_abort emb_mdb_txn_abort
#define mdb_txn_begin emb_mdb_txn_begin
#define mdb_txn_commit emb_mdb_txn_commit
#define mdb_txn_env emb_mdb_txn_env
#define mdb_txn_id emb_mdb_txn_id
#define mdb_txn_renew emb_mdb_txn_renew
#define mdb_txn_reset emb_mdb_txn_reset
#define mdb_version emb_mdb_version
#define mdb_mid2l_append emb_mdb_mid2l_append
#define mdb_mid2l_insert emb_mdb_mid2l_insert
#define mdb_mid2l_search emb_mdb_mid2l_search
#define mdb_midl_alloc emb_mdb_midl_alloc
#define mdb_midl_append emb_mdb_midl_append
#define mdb_midl_append_list emb_mdb_midl_append_list
#define mdb_midl_append_range emb_mdb_midl_append_range
#define mdb_midl_free emb_mdb_midl_free
#define mdb_midl_need emb_mdb_midl_need
#define mdb_midl_search emb_mdb_midl_search
#define mdb_midl_shrink emb_mdb_midl_shrink
#define mdb_midl_sort emb_mdb_midl_sort
#define mdb_midl_xmerge emb_mdb_midl_xmerge
