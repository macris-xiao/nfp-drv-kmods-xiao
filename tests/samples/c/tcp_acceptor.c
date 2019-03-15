// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2003 Davide Libenzi */
/* Copyright (C) 2019 Netronome Systems, Inc. */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include "lib/samples.h"

#define MAX_EVENTS 100

static const char *bin;

static void usage(int exit_code)
{
	fprintf(stderr,
		"Usage: %s OPTIONS -p <port>\n"
		"\n"
		"This program implements a simple TCP server which only accepts\n"
		"connections. No data can ever be sent to the server (otherwise\n"
		"server will close the connection, and no data will be received\n"
		"from the server. The only purpose is to test connection rate.\n"
		"\n"
		"\t-p|--port       <port> port or service name to connect to\n"
		"    OPTIONS:\n"
		"\t-4|--ipv4-only  force the use of IPv4\n"
		"\t-6|--ipv6-only  force the use of IPv6\n"
		"\t-h|--help       print help and exit\n"
		"", bin);
	exit(exit_code);
}

int main(int argc, char *const *argv)
{
	static const struct option options[] = {
		{ "port",	required_argument,	NULL,	'p' },
		{ "ipv4-only",	no_argument,		NULL,	'4' },
		{ "ipv6-only",	no_argument,		NULL,	'6' },
		{ "help",	no_argument,		NULL,	'h' },
		{ 0 }
	};
	struct epoll_event ev, events[MAX_EVENTS];
	int sock, conn_sock, nfds, epollfd;
	struct addrinfo *addrinfo, hints;
	const char *port = NULL;
	struct rlimit rlim;
	int opt, err, n;

	bin = argv[0];

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "46hp:",
				  options, NULL)) >= 0) {
		switch (opt) {
		case '4':
		case '6':
			if (hints.ai_family)
				return err_ret(1, "family already set\n");
			hints.ai_family = opt == '4' ? AF_INET : AF_INET6;
			break;
		case 'p':
			port = argv[optind - 1];
			break;
		case 'h':
			usage(0);
			break;
		default:
			err_msg("unrecognized option '%s'\n", argv[optind - 1]);
			usage(1);
		}
	}

	if (!port)
		return err_ret(2, "port/service name not specified\n");

	/* Resolved destination */
	err = getaddrinfo(NULL, port, &hints, &addrinfo);
	if (err) {
		err_msg("can't resolve the port: %s\n",	gai_strerror(err));
		return 1;
	}

	sock = ls_socket_tcp_listen(addrinfo, 1000);
	freeaddrinfo(addrinfo);
	if (sock < 0)
		return -sock;

	err = ls_socket_set_reuse_opts(sock);
	if (err)
		return err;

	err = ls_sched_set_rt();
	if (err)
		return err;

	err = getrlimit(RLIMIT_NOFILE, &rlim);
	if (err)
		return err_ret(4, "getrlimit: %s\n", strerror(errno));

	rlim.rlim_cur = rlim.rlim_max;
	err = setrlimit(RLIMIT_NOFILE, &rlim);
	if (err)
		return err_ret(5, "setrlimit: %s\n", strerror(errno));


	epollfd = epoll_create1(0);
	if (epollfd < 0)
		return err_ret(6, "epoll_create1: %s\n",
			       strerror(errno));

	ev.events = EPOLLIN;
	ev.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) < 0)
		return err_ret(7, "epoll_ctl: listen_sock: %s\n",
			       strerror(errno));

	for (;;) {
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if (nfds < 0)
			return err_ret(8, "epoll_wait: %s\n", strerror(errno));

		for (n = 0; n < nfds; ++n) {
			/* Whenever client gets active, close it.
			 * Clients should not send data, active means it died.
			 */
			if (events[n].data.fd != sock) {
				close(events[n].data.fd);
				continue;
			}

			conn_sock = accept(sock, NULL, NULL);
			if (conn_sock < 0)
				return err_ret(9, "accept: %s\n",
					       strerror(errno));

			fcntl(conn_sock, F_SETFL, O_NONBLOCK);

			ev.events = EPOLLIN | EPOLLET;
			ev.data.fd = conn_sock;
			if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev))
				return err_ret(10, "epoll_ctl: conn_sock: %s\n",
					       strerror(errno));
		}
	}

	close(sock);

	return 0;
}
