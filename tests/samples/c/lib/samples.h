// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Netronome Systems, Inc. */

#ifndef _LIB_SAMPLES_H_
#define _LIB_SAMPLES_H_

#include <stdio.h>

struct addrinfo;

#define pr(msg...)		fprintf(stderr, msg)
#define err_msg(msg...)		pr("Error: " msg)
#define err_ret(ret, msg...)	({ pr("Error: " msg); ret; })

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof(a[0]))

int ls_sched_set_rt(void);

int ls_socket_set_reuse_opts(int sock);
int ls_socket_tcp_connect(struct addrinfo *addrinfo);
int ls_socket_tcp_listen(struct addrinfo *addrinfo, int backlog);

#endif
