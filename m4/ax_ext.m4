# ===========================================================================
#                 http://autoconf-archive.cryp.to/ax_ext.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_EXT
#
# DESCRIPTION
#
#   Find supported SIMD extensions by requesting cpuid. When an SIMD
#   extension is found, the -m"simdextensionname" is added to SIMD_FLAGS
#   (only if compilator support it) (ie : if "sse2" is available "-msse2" is
#   added to SIMD_FLAGS)
#
#   This macro calls:
#
#     AC_SUBST(SIMD_FLAGS)
#
#   And defines:
#
#     HAVE_MMX / HAVE_SSE / HAVE_SSE2 / HAVE_SSE3 / HAVE_SSSE3
#
# LAST MODIFICATION
#
#   2008-04-12
#   2009-04-23  Mark Asbach <markasbach@users.sourceforge.net<
#               Renamed cache variables so they adhere naming convention
#               Corrected M4 quoting for AX_CHECK_COMPILER_FLAGS
#
# COPYLEFT
#
#   Copyright (c) 2008 Christophe Tournayre <turn3r@users.sourceforge.net>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved.

AC_DEFUN([AX_EXT],
[
  AC_REQUIRE([AX_GCC_X86_CPUID])
  
  AX_GCC_X86_CPUID([0x00000001])
  if test "$ax_cv_gcc_x86_cpuid_0x00000001" != "unknown"; then
    ecx=`echo $ax_cv_gcc_x86_cpuid_0x00000001 | cut -d ":" -f 3`
    edx=`echo $ax_cv_gcc_x86_cpuid_0x00000001 | cut -d ":" -f 4`
  fi
  
  AC_CACHE_CHECK([whether mmx is supported], [ax_cv_have_mmx_ext],
  [
    ax_cv_have_mmx_ext=no
    if test "$ax_cv_gcc_x86_cpuid_0x00000001" != "unknown"; then
      if test "$((0x$edx>>23&0x01))" = 1; then
        ax_cv_have_mmx_ext=yes
      fi
    fi
  ])

  AC_CACHE_CHECK([whether sse is supported], [ax_cv_have_sse_ext],
  [
    ax_cv_have_sse_ext=no
    if test "$ax_cv_gcc_x86_cpuid_0x00000001" != "unknown"; then
      if test "$((0x$edx>>25&0x01))" = 1; then
        ax_cv_have_sse_ext=yes
      fi
    fi
  ])

  AC_CACHE_CHECK([whether sse2 is supported], [ax_cv_have_sse2_ext],
  [
    ax_cv_have_sse2_ext=no
    if test "$((0x$edx>>26&0x01))" = 1; then
      ax_cv_have_sse2_ext=yes
    fi
  ])

  AC_CACHE_CHECK([whether sse3 is supported], [ax_cv_have_sse3_ext],
  [
    ax_cv_have_sse3_ext=no
    if test "$ax_cv_gcc_x86_cpuid_0x00000001" != "unknown"; then
      if test "$((0x$ecx&0x01))" = 1; then
        ax_cv_have_sse3_ext=yes
      fi
    fi
  ])

  AC_CACHE_CHECK([whether ssse3 is supported], [ax_cv_have_ssse3_ext],
  [
    ax_cv_have_ssse3_ext=no
    if test "$ax_cv_gcc_x86_cpuid_0x00000001" != "unknown"; then
      if test "$((0x$ecx>>9&0x01))" = 1; then
        ax_cv_have_ssse3_ext=yes
      fi
    fi
  ])

  if test "$ax_cv_have_mmx_ext" = yes; then
    AC_DEFINE(HAVE_MMX,,[Support mmx instructions])
    AX_CHECK_COMPILER_FLAGS([-mmmx], [SIMD_FLAGS="$SIMD_FLAGS -mmmx"], [])
  fi

  if test "$ax_cv_have_sse_ext" = yes; then
    AC_DEFINE(HAVE_SSE,,[Support SSE (Streaming SIMD Extensions) instructions])
    AX_CHECK_COMPILER_FLAGS([-msse], [SIMD_FLAGS="$SIMD_FLAGS -msse"], [])
  fi

  if test "$ax_cv_have_sse2_ext" = yes; then
    AC_DEFINE(HAVE_SSE2,,[Support SSE2 (Streaming SIMD Extensions 2) instructions])
    AX_CHECK_COMPILER_FLAGS([-msse2], [SIMD_FLAGS="$SIMD_FLAGS -msse2"], [])
  fi

  if test "$ax_cv_have_sse3_ext" = yes; then
    AC_DEFINE(HAVE_SSE3,,[Support SSE3 (Streaming SIMD Extensions 3) instructions])
    AX_CHECK_COMPILER_FLAGS([-msse3], [SIMD_FLAGS="$SIMD_FLAGS -msse3"], [])
  fi

  if test "$ax_cv_have_ssse3_ext" = yes; then
    AC_DEFINE(HAVE_SSSE3,,[Support SSSE3 (Supplemental Streaming SIMD Extensions 3) instructions])
  fi

  AC_SUBST(SIMD_FLAGS)
])
