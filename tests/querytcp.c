/*
TCP query version of queryperf
querytcp.c
				fujiwara@jprs.co.jp
				2009.08.12
				version 0.4

queryperf for tcp query

This program measures DNS server performance of TCP query.

o Running environment:
	Development environment:
        Linux
		FreeBSD
		MacOS X 10.3.4

o How to make:
    Linux:   gcc -D_LINUX -Wall -O2 -g -lm -o querytcp querytcp.c
    FreeBSD: gcc -Wall -O2 -g -lm -o querytcp querytcp.c
    MacOS X: gcc -Wall -O2 -g -lm -lresolv -o querytcp querytcp.c

o changes

  2010/6/7: Linux compatibility
  2009/8/12: Remove use of res_mkquery
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <errno.h>
#include <math.h>
#include <err.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <math.h>
#ifndef NO_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef __APPLE__
#include <nameser8_compat.h>
#endif

#ifndef ns_t_soa
#define	ns_t_soa	T_SOA
#endif
#ifndef ns_t_ns
#define	ns_t_ns		T_NS
#endif
#ifndef ns_c_in
#define	ns_c_in		C_IN
#endif

#ifdef NOINET6
#undef AF_INET6
#endif

#define	Global

#ifndef PACKETSZ
#define	PACKETSZ	512
#endif

/* debug.c */
void hexdump(char *title, unsigned char *memory, int len)
{
	printf("[ %s ", title);
	while (len-- > 0)
		printf("%02x ", *memory++);
	printf("]\n");
}

#define Xmalloc(size)	Xrealloc(NULL, size)

void *Xrealloc(void *p, int size)
{
	int sz;

	sz = (size > 0) ? size : -size;
	if (p == NULL) {
		p = malloc(sz);
	} else {
		p = realloc(p, sz);
	}
	if (p == NULL) {
		char buf[100];
		snprintf(buf, sizeof buf, "size=%d", size);
		perror(buf);
		exit(1);
	}
	if (size < 0)
		memset(p, 0, sz);
	return p;
}

/* strlcpy() emulation for Linux. */
#ifdef _LINUX
static inline size_t strlcpy(char *destination, const char *source, size_t size)
{
    if(strncpy(destination, source, size) == NULL)
        return 0;

    return size;
}
#endif

/*
  NULL ... returns NULL
 */
char *Xstrdup(char *p)
{
	char *q;
	int len;

	if (p == NULL)
		return NULL;
	len = strlen(p) + 1;
	q = Xmalloc(len);
	strlcpy(q, p, len);
	return q;
}


typedef int64_t timediff_t;

/* packet buffer */
static struct timeval current;
static struct timeval start, send_finished;;
static fd_set fdset0r, fdset0w;
static int nfds;
static struct sockaddr_storage remote;
static int remote_len = 0;
static int finished = 0;
static timediff_t Timeout = 10*1000000LL;
unsigned short counter = 0;

#define	UpdateCurrentTime		gettimeofday(&current, NULL)

#define	RECVBUFSIZ	65537
#define	SENDBUFSIZ	512

struct dnsheader  {
  unsigned short id; // 2
  unsigned char flag1, flag2; // 2
  unsigned short qdcount, ancount, nscount, arcount; // 8
};

/*
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
	
struct queries {
	struct tcpdns {
		unsigned short len;
		union {
			struct dnsheader h;
			unsigned char dnsdata[SENDBUFSIZ];
		} u;
	} send;
	unsigned char recvbuf[RECVBUFSIZ];
	int sendlen;
	int sent_flag:1;
	int tcpstate:2;
	int fd;
	int rpos;
	int wpos;
	int no;
	struct timeval sent; /* long tv_sec, long tv_usec */
};

struct queries *Queries;

#define	NQUERY 100

#define	TCP_NONE	0
#define	TCP_WRITABLE	1
#define	TCP_READABLE	2

/* input */
char *ServerName = "127.0.0.1";
char *ServerPort = "53";
int family = PF_UNSPEC;
char *datafile = NULL;
int TimeLimit = 20;
int EDNS0 = 0;
int DNSSEC = 0;
int recursion = 0;
FILE *fp = NULL;
int datafileloop = 0;
int verbose = 0;
int nQueries = 120;
int printrcode = 0;
char *rcodestr[]= {
	"NOERROR", "FormatError", "ServerFailure", "NameError",
	"NotImplemented", "Reused", "RCODE06", "RCODE07",
	"RCODE08", "RCODE09", "RCODE10", "RCODE11",
	"RCODE12", "RCODE13", "RCODE14", "RCODE15",
};

timediff_t timediff(struct timeval *a, struct timeval *b) /* u sec */
{
	return (a->tv_sec - b->tv_sec) * 1000000 + (a->tv_usec - b->tv_usec);
}

#define	TIMEOUTERROR	-10000
#define	ERROROFFSET	-20000
#define	ERRZEROREAD	-30000

uint64_t countrcode[16];
uint64_t response_size_sum = 0;
uint64_t response_size_sum2 = 0;
uint64_t countanswers = 0;
uint64_t countqueries = 0;
uint64_t countzeroread = 0;
uint64_t counttimeout = 0;
uint64_t counterror = 0;

int response_size_min = 0;
int response_size_max = 0;



void register_response(struct queries *q, int timeout, char *note)
{
	u_char *p;
	int size;
	int rcode;
	int id;

    id = ntohs(q->send.u.h.id);
	if (note == NULL)
		note = "";
	countqueries++;
	if (timeout >= 0) {
		p = q->recvbuf;
		NS_GET16(size, p);
		response_size_sum += size;
		response_size_sum2 += size * size;
		if (response_size_min == 0 || response_size_min > size)
			response_size_min = size;
		if (response_size_max == 0 || response_size_max < size)
			response_size_max = size;
		rcode = p[3] & 0x0f;
		countrcode[rcode]++;
		countanswers++;
		if (verbose)
			printf("recv response id=%d rcode=%d size=%d rtt=%d\n", id, rcode, size, timeout);
	} else if (timeout == ERRZEROREAD) {
		countzeroread++;
		if (verbose)
			printf("recv response id=%d zeroread\n", id);
	} else if (timeout == TIMEOUTERROR) {
		counttimeout++;
		if (verbose)
			printf("recv timeout id=%d %lld usec\n", id, timediff(&current, &q->sent));
	} else {
		counterror++;
		if (verbose) {
			printf("recv error id=%d errno=%d at %s (%s)\n", id, ERROROFFSET - timeout, note, strerror(errno));
		}
	}
#ifdef DEBUG
    printf("%ld.%03ld no=%d fd=%d %d %s\n", q->sent.tv_sec, q->sent.tv_usec/1000, q->no, q->fd, timeout, note);
	fflush(stdout);
#endif
}

void output()
{
	double response_size_average, response_size_variance, et;

	et = ((double)timediff(&current, &start))/1000000.0;

	printf("elapsed time: %.3f\n", et);
	printf("tcp qps: %.3f\n", (double)countanswers/et);
	printf("sent: %lld\n", countqueries);
	printf("answer: %lld  %3.1f%%\n", countanswers,
		 (double)((double)countanswers/(double)countqueries*100.0));
	printf("error: %lld  %3.1f%%\n", counterror,
		 (double)((double)counterror/(double)countqueries*100.0));
	printf("zeroread: %lld  %3.1f%%\n", countzeroread,
		 (double)((double)countzeroread/(double)countqueries*100.0));
	printf("timeout: %lld  %3.1f%%\n", counttimeout,
		 (double)((double)counttimeout/(double)countqueries*100.0));
	response_size_average = (double)response_size_sum/countanswers;
	response_size_variance = (double)response_size_sum2 / countanswers
		- response_size_average * response_size_average;
	printf("response size:        %d/%.3f/%d/%.3f bytes\n", response_size_min, response_size_average, response_size_max, sqrt(response_size_variance));
	if (printrcode) {
		int i;
		for (i = 0; i < 16; i++) {
			if (countrcode[i] != 0) {
				printf("%s %lld %5.1f\n", rcodestr[i], countrcode[i], ((double)countrcode[i])/((double)countanswers)*100.0);
			}
		}
	}
}

void tcp_close(struct queries *q)
{

#ifdef DEBUG
printf("tcp_close no=%d fd=%d\n", q->no, q->fd);
#endif
	if (q->fd >= 0) {
		close(q->fd);
		FD_CLR(q->fd, &fdset0r);
		FD_CLR(q->fd, &fdset0w);
	}
	q->sent_flag = 0;
	q->tcpstate = TCP_NONE;
	q->fd = -1;
}

void tcp_send(struct queries *q)
{
	int len;

	len = send(q->fd, &q->send, q->sendlen, MSG_NOSIGNAL);
#ifdef DEBUG
printf("tcp_send no=%d fd=%d %d:%d:%d\n", q->no, q->fd, len, q->wpos, q->sendlen);
#endif
	if (len < 0) {
		if (errno == ENOTCONN) {
printf("tcp_send no=%d fd=%d ENOTCONN return\n", q->no, q->fd);
			return;
		}
		register_response(q, ERROROFFSET - errno, "tcp_send");
		tcp_close(q);
		return;
	}
	if (len != q->sendlen) {
		register_response(q, ERROROFFSET - errno, "tcp_send:sendto");
		tcp_close(q);
		return;
	}
	FD_CLR(q->fd, &fdset0w);
	FD_SET(q->fd, &fdset0r);
}

struct typecodes {
	char *name;
	int code;
} typecodes[] = {
	{ "A", ns_t_a },
	{ "NS", ns_t_ns },
	{ "SOA", ns_t_soa },
	{ "PTR", ns_t_ptr },
	{ "HINFO", ns_t_hinfo },
	{ "MX", ns_t_mx },
	{ "TXT", ns_t_txt },
	{ "SIG", ns_t_sig },
	{ "KEY", ns_t_key },
	{ "AAAA", ns_t_aaaa },
	{ "NXT", ns_t_nxt },
	{ "SRV", ns_t_srv },
	{ "NAPTR", ns_t_naptr },
	{ NULL, -1 },
};

int stringtodname(unsigned char *qname, unsigned char *buff, unsigned char *lim)
{
	unsigned char *p, *s, *t;
	int count, total;

	t = qname;
	p = buff;
	total = 0;
	for ( ;; ) {
		s = p++;
		count = 0;
		if (p >= lim) return -1;
		while (*t != 0 && *t != '.')
			if (p < lim) {
				*p++ = *t++;
				count++;
			} else
				return -1;
		*s = count;
		if (count == 0)
			break;
		if (count > 63)
			return -1;
		total += count + 1;
		if (*t == '.') t++;
	}
	if (total > 250 || !(*t == 0 || (*t == '.' && t[1] == 0)))
		return -1;
	return p - buff;
}

void send_query_error(char *mesg)
{
	err(1, "Packet size exceed: %s", mesg);
}

void send_query(struct queries *q)
{
    u_char *p, *lim;
    char *qname;
	int qclass;
	int qtype;
	int tmp;
	struct typecodes *t = typecodes;
	u_char buff[512];
	static char sep[] = "\n\t ";
	static int lineno = 0;

	/*
		SEND E[send_packet_pos]
	 */
	if (q->sent_flag) {
		register_response(q, TIMEOUTERROR, "send_query");
		tcp_close(q);
	}
	if (fp == NULL) {
		qname = "version.bind";
		qclass = ns_c_chaos;
		qtype = ns_t_txt;
	} else {
		do {
            if (fgets((char*)buff, sizeof(char)*512, fp) == NULL) {
				if (datafileloop == 1) {
					finished = 1;
					fclose(fp);
					fp = NULL;
					return;
				}
				if (datafileloop > 0)
					datafileloop--;
				rewind(fp);
				lineno = 0;
                if (fgets((char*)buff, sizeof(char)*512, fp) == NULL)
					err(1, "cannot rewind input file");
			}
			lineno++;
		} while(buff[0] == '#');
        qname = strtok((char*)buff, sep);
        p = (u_char*) strtok(NULL, sep);
		if (p != NULL) {
			while(t->name != NULL) {
                if (!strcasecmp(t->name, (char*)p))
					break;
				t++;
			}
			qtype = t->code;
		} else {
			qtype = ns_t_a;
		}
		if (qname == NULL || qtype < 0)
			err(1, "datafile format error at line %d, qname=%s qtype=%d", lineno, qname, qtype);
		qclass = ns_c_in;
	}
	q->send.u.h.id = counter++;
	q->send.u.h.flag1 = recursion ? 1 : 0; /* Query,OP=0,AA=0,TC=0,RD=0/1 */
	q->send.u.h.flag2 = 0;
	q->send.u.h.qdcount = htons(1);
	q->send.u.h.ancount = 0;
	q->send.u.h.nscount = 0;
	q->send.u.h.arcount = 0;
	p = q->send.u.dnsdata + sizeof(q->send.u.h);
	lim = p + sizeof(q->send.u.dnsdata);
    if ((tmp = stringtodname((u_char*) qname, p, lim)) < 0)
		send_query_error(qname);
	p += tmp;
	*(unsigned short *)p = htons(qtype);
	p += sizeof(unsigned short);
	*(unsigned short *)p = htons(qclass);
	p += sizeof(unsigned short);
	q->sendlen = p - q->send.u.dnsdata;
	if (EDNS0) {
#define EDNS0size 11
		if (q->sendlen + EDNS0size >= sizeof(q->send.u.dnsdata))
			send_query_error("ENDS0");
		*p++ = 0; /* . */
		*(unsigned short *)p = htons(ns_t_opt);
		p += 2;
		*(unsigned short *)p = htons(4096);
		p += 2;
		*p++ = 0;
		*p++ = 0;
		*p++ = (DNSSEC == 0) ? 0 : 0x80; /* eflag: DO bit */
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		q->sendlen += EDNS0size;
        p = (u_char*) &q->send.u.dnsdata;
		q->send.u.h.ancount = htons(1);
	}
	q->send.len = htons(q->sendlen);
	q->sendlen += sizeof(q->send.len);
	q->wpos = 0;
	q->rpos = 0;
	q->sent = current;
	if (verbose > 0) {
		int id = ntohs(*(unsigned short *)&q->send.u.dnsdata);
		printf("sending query(%s,%d,%d) id=%d %d bytes to %s\n", qname, qclass, qtype, id, q->sendlen, ServerName);
        hexdump("sending packet header:", (unsigned char*) &q->send.u.h, 12);
	}
	if (q->fd > 0)
		err(1, "q->fd > 0 but ignored\n");

	q->fd = socket(remote.ss_family, SOCK_STREAM, 0);
	tmp = fcntl(q->fd, F_GETFL, 0);
	fcntl(q->fd, F_SETFL, O_NONBLOCK | tmp);
	int conn_ret = connect(q->fd, (struct sockaddr *)&remote, remote_len);
	if(conn_ret < 0 && errno != EINPROGRESS) {
		register_response(q, ERROROFFSET - errno, "send_query:socket+fcntl+connect");
		tcp_close(q);
		return;
	}
#ifdef DEBUG
printf("send_query no=%d fd=%d socket|connect\n", q->no, q->fd);
#endif
	q->tcpstate = TCP_WRITABLE;
	FD_SET(q->fd, &fdset0w);
	FD_CLR(q->fd, &fdset0r);
	if (nfds <= q->fd) {
		nfds = q->fd + 1;
	}
	q->sent = current;
	q->sent_flag = 1;
}

int UpdateQuery()
{
	int i;
	timediff_t t, min = Timeout;
	struct queries *q;
	int free = 0;

	if (!finished && TimeLimit > 0) {
		if ((t = timediff(&current, &start)) > TimeLimit * 1000000LL) {
			finished = 1;
			send_finished = current;
		}
	}
	for(i = 0; i < nQueries; i++) {
		q = &Queries[i];
		if (q->sent_flag) {
			if ((t = timediff(&current, &q->sent)) > Timeout) {
				/* timeouted */
				register_response(q, TIMEOUTERROR, "UpdateQuery");
				tcp_close(q);
			} else
			if (t < min)
				min = t;
		}
		if (!q->sent_flag) {
			if (!finished)
				send_query(q);
			else
				free++;
		}
	}
	if (free == nQueries)
		min = -1; /* finished */
	return min;
}

char *skipname(char *p)
{
	while(*p > 0 && *p < 0x40) p += *p + 1;
	if (*p == 0)
		return p+1;
	return p+2;
}

#define Hexdump(A,B,C)

void tcp_receive(struct queries *q)
{
	int len, len2;
	timediff_t tmp;
	unsigned char *recvp;

/*printf("tcp_receive %s\n", q->nameserverlabel);*/

	len = read(q->fd, q->recvbuf + q->rpos, len2 = RECVBUFSIZ - q->rpos);
	if (len < 0) {
		if (errno == EAGAIN)
			return;
		register_response(q, ERROROFFSET - errno, "tcp_receive:read");
		tcp_close(q);
		return;
	}
	if (len == 0) {
		register_response(q, ERRZEROREAD, "tcp_receive:read");
		tcp_close(q);
		return;
	}
	q->rpos += len;
	if (q->rpos < 2)
		return;
	len2 = ntohs(*(unsigned short *)(q->recvbuf));
	if (q->rpos >= len2 + 2) {
		/* finished */
		recvp = q->recvbuf + 2;
		if (memcmp(recvp, q->send.u.dnsdata, 2) == 0) {
			if ((recvp[2] & 1) == 0 /* RA bit */
			  || (recvp[3] & 15) != 0 /* RCODE must be 0 */
			) {
/*
				fprintf(stderr, "WRONG AA=%d RCODE=%d\n",
					((recvp[2]>>2) & 1), recvp[3]&15);
*/
			}
			tmp = timediff(&current, &q->sent);
			register_response(q, tmp, "tcp_receive");
			tcp_close(q);
			return;
		} else {
printf("no=%d fd=%d unknown recv %d bytes, len=%d\n", q->no, q->fd, q->rpos, ntohs(*(unsigned short *)(q->recvbuf)));
			hexdump("", q->recvbuf, len);
			/*
			fprintf(stderr, "unknown recv from %s, %d bytes %02x %02x\n", q->nameserverlabel, q->rpos, recvp[0], recvp[1]);
			*/
			tcp_close(q);
		}
	}
}

void query()
{
	fd_set fdsetr, fdsetw;
	struct timeval timeout;
	int min;
	struct queries *q;
	int i, n;
	struct addrinfo hints, *res0;
	int error;

	Queries = Xmalloc(sizeof(Queries[0]) * nQueries);
	memset(&remote, 0, sizeof(remote));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	printf("resolving: %s:%s\n", ServerName, ServerPort);
	error = getaddrinfo(ServerName, 0, &hints, &res0);
	if (error) {
		errx(1, "%s", gai_strerror(error));
	}

	/* Update server port. */
	int port = atoi(ServerPort);
	if (res0->ai_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)res0->ai_addr;
		ipv6->sin6_port = htons(port);
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in*)res0->ai_addr;
		ipv4->sin_port = htons(port);
	}

	remote_len = res0->ai_addrlen;
	memcpy(&remote, res0->ai_addr, res0->ai_addrlen);
	memset(&countrcode, 0, sizeof(countrcode));

	res_init();
	_res.options ^= ~RES_RECURSE;
	_res.options |= RES_AAONLY;

	for (i = 0; i < nQueries; i++) {
		Queries[i].sent_flag = 0;
		Queries[i].no = i;
	}

	FD_ZERO(&fdset0r);
	FD_ZERO(&fdset0w);
	nfds = 0;
	UpdateCurrentTime;
	start = current;
	finished = 0;

	for (;;) {
		UpdateCurrentTime;
		if ((min = UpdateQuery()) < 0)
			break;
		timeout.tv_sec = min / 1000000;
		timeout.tv_usec = min % 1000000;
		fdsetr = fdset0r;
		fdsetw = fdset0w;
		n = select(nfds, &fdsetr, &fdsetw, NULL, &timeout);
		UpdateCurrentTime;
		for(i = 0; i < nQueries; i++) {
			q = &Queries[i];
			if (q->fd < 0 || !q->sent_flag)
				continue;
			if (FD_ISSET(q->fd, &fdsetw)) {
				tcp_send(q);
			} else if (FD_ISSET(q->fd, &fdsetr)) {
				tcp_receive(q);
			}
		}
	}
}

void usage()
{
	fprintf(stderr, 
"querytcp [-d datafile] [-s server_addr] [-p port] [-q num_queries] [-t timeout] [l limit] [-4] [-6] [-h]\n"
"  -d specifies the input data file (default: stdin)\n"
"  -s sets the server to query (default: 127.0.0.1)\n"
"  -p sets the port on which to query the server (default: 53)\n"
"  -q specifies the maximum number of queries outstanding (default: 120)\n"
"  -t specifies the timeout for query completion in seconds (default: 10)\n"
"  -l specifies how a limit for how long to run tests in seconds (no default)\n"
"  -e enable EDNS0\n"
"  -D set DO bit\n"
"  -r set RD bit\n"
"\n"
"\n"
"\n"
"  -c print the number of packets with each rcode\n"
"  -v verbose: report the RCODE of each response on stdout\n"
"  -h print this usage\n"
);
	exit(1);
}

int main(int argc, char *argv[])
{
	int ch, i;
    printf("dnsheader size: %d\n", sizeof(struct dnsheader));
	while ((ch = getopt(argc, argv, "d:s:p:q:t:l:46eDrvh")) != -1) {
	switch (ch) {
	case 'q':
		nQueries = atoi(optarg);
		if (nQueries < 1)
			err(1, "-q requires natural number");
		break;
	case 'p':
		ServerPort = Xstrdup(optarg);
		break;
	case 's':
		ServerName = Xstrdup(optarg);
		break;
	case 'd':
		datafile = Xstrdup(optarg);
		if ((fp = fopen(datafile, "r")) == NULL)
			err(1, "cannot open %s", optarg);
		break;
	case 't':
		i = atoi(optarg);
		if (i < 1)
			err(1, "-t timeout > 0");
		Timeout = (int64_t)i * 1000000LL;
		break;
	case 'l':
		TimeLimit = atoi(optarg);
		break;
	case '4':
		family = AF_INET;
		break;
	case '6':
		family = AF_INET6;
		break;
	case 'e':
		EDNS0 = 1;
		break;
	case 'D':
		DNSSEC = 1;
		break;
	case 'r':
		recursion = 1;
		break;
	case 'v':
		verbose = 1;
		break;
	case 'c':
		printrcode = 1;
		break;
	case 'h':
	default:
		usage();
	}
	}
	argc -= optind;
	argv += optind;

	query();
	output();

	return 0;
}
