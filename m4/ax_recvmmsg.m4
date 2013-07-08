dnl @synopsis AX_MSG_WAITFORONE
dnl @summary Test if the libc/kernel have working recvmmsg MSG_WAITFORONE implementation
dnl @category Misc
dnl
dnl We need recvmmsg to support MSG_WAITFORONE.  RHEL 6 (and derivates)
dnl are know for broken implementation
dnl
dnl @version 2013-03-12
dnl @license GPL
dnl @author Ondřej Surý <ondrej@sury.org> and Marek Vavruša <marek@vavrusa.com>

AC_DEFUN([AX_MSG_WAITFORONE],
[
  AC_REQUIRE([AC_PROG_CC])

  AC_LANG_PUSH([C])

  AC_CACHE_CHECK([for recv_mmsg support], [ax_cv_have_msg_waitforone],
  [
    AC_RUN_IFELSE(
    [
      AC_LANG_PROGRAM(
      [[
#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

volatile int _intr = 0;
void sighandle(int s) {
     _intr = 1;
}
      ]],[[
#ifndef MSG_WAITFORONE
  return 3; /* Not supported. */
#else
  int port = 35353;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return 1;
  struct mmsghdr msgs[2];
  struct iovec iovecs[2];
  char bufs[2][64];
  unsigned i = 0;
  memset(msgs, 0, sizeof(msgs));
  for (i = 0; i < 2; i++) {
    iovecs[i].iov_base = bufs[i];
    iovecs[i].iov_len = 64;
    msgs[i].msg_hdr.msg_iov = &iovecs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }

  struct sockaddr_in sa; /* Bind to socket. */
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port); /* Find free port. */
  while (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
  if (errno == EADDRINUSE) sa.sin_port = ++port;
  else break;
  }

  int cfd = socket(AF_INET, SOCK_DGRAM, 0); /* Send datagram. */
  char pkt[32] = { '\xdf' };
  sendto(cfd, pkt, sizeof(pkt), 0, (struct sockaddr*)&sa, sizeof(sa));

  /* Broken implementation doesn't respect recvmmsg timeout. */
  struct sigaction aset;
  memset(&aset, 0, sizeof(struct sigaction));
  aset.sa_handler = sighandle;
  sigaction(SIGALRM, &aset, NULL);
  alarm(1);

  int ret = recvmmsg(fd, msgs, 2, MSG_WAITFORONE, NULL);
  close(cfd);
  close(fd);
  if (ret < 0) { /* Completely failed. */
    return 2;
  }

  return _intr; /* OK if not interrupted. */
#endif
    ]])],
  [ax_cv_have_msg_waitforone=yes],
  [ax_cv_have_msg_waitforone=no],
  [ax_cv_have_msg_waitforone=no])])

  AC_LANG_POP([C])
])
