// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Netronome Systems, Inc. */

#ifndef _LIB_SAMPLES_H_
#define _LIB_SAMPLES_H_

#include <stdio.h>

#define pr(msg...)		fprintf(stderr, msg)
#define err_msg(msg...)		pr("Error: " msg)
#define err_ret(ret, msg...)	({ pr("Error: " msg); ret; })

int ls_sched_set_rt(void);

int ls_socket_set_reuse_opts(int sock);

#endif
