// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <netdb.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "samples.h"

/* libsamples should try to always print an error when something fails.
 * This should save callers printing. Every operation should have it's
 * own error return code.
 *
 * Error return codes:
 * 101 - reuse socket opts
 * 102 - sched set rt
 * 103 - TCP listen
 * 104 - TCP connect
 */

int ls_sched_set_rt(void)
{
	struct sched_param sched_param = { .sched_priority = 50, };

	if (sched_setscheduler(0, SCHED_FIFO, &sched_param))
		return err_ret(102, "set RT prio failed: %s\n",
			       strerror(errno));
	return 0;
}

int ls_socket_set_reuse_opts(int sock)
{
	int opt;

	opt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
		return err_ret(101, "set reuseaddr failed: %s\n",
			       strerror(errno));

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)))
		return err_ret(101, "set reuseport failed: %s\n",
			       strerror(errno));
	return 0;
}

int ls_socket_tcp_connect(struct addrinfo *addrinfo)
{
	struct addrinfo *ai;
	int fd;

	for (ai = addrinfo; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		if (!connect(fd, ai->ai_addr, ai->ai_addrlen))
			return fd;

		close(fd);
	}

	return err_ret(-104, "unable to connect to the specified server\n");
}

int ls_socket_tcp_listen(struct addrinfo *addrinfo, int backlog)
{
	struct addrinfo *ai;
	int fd;

	for (ai = addrinfo; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		if (!bind(fd, ai->ai_addr, ai->ai_addrlen) &&
		    !listen(fd, backlog))
			return fd;

		close(fd);
	}

	return err_ret(-103,
		       "unable to bind & listen on any of the addresses\n");
}
