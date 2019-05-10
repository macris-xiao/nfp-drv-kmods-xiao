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
