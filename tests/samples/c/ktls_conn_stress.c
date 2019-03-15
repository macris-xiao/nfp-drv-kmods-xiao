// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "lib/samples.h"

static int opt_keep;
static int opt_conns = 1;
static bool opt_tx = true;
static bool opt_rx = true;
static int opt_sleep;
static unsigned int opt_tls_version = TLS_1_2_VERSION;

static const char *bin;
static struct addrinfo *ai;
#define NUM_TIME_MAXES		5
static struct shared {
	sem_t sem;
	long max_t[NUM_TIME_MAXES];
} *shared;

static long max_t[NUM_TIME_MAXES];

static long __my_clock(void)
{
	struct timespec tp;

	clock_gettime(CLOCK_MONOTONIC_RAW, &tp);

	return tp.tv_sec * 1000 * 1000 * 1000 + tp.tv_nsec;
}
#define clock __my_clock

static long clock_to_us(long t)
{
	return t / 1000;
}

#define END_T(idx)					\
	({						\
		end = clock();				\
		if (end - start > max_t[idx])		\
			max_t[idx] = end - start;	\
	})

static int
do_tls_conn(int fd, struct tls12_crypto_info_aes_gcm_128 *crypto_info)
{
	clock_t start, end;
	struct linger tw;

	start = clock();
	if (connect(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		perror("    Failed to connect");
		return 1;
	}
	END_T(0);

	tw.l_onoff = 1;
	tw.l_linger = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &tw, sizeof(tw))) {
		perror("    Can't disable linger");
		return 1;
	}

	start = clock();
	if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))) {
		perror("    Can't enable tls");
		return 1;
	}
	END_T(1);


	start = clock();
	if (opt_tx && setsockopt(fd, SOL_TLS, TLS_TX, crypto_info,
				 sizeof(*crypto_info))) {
		perror("    Can't set TX");
		return 1;
	}
	END_T(2);

	start = clock();
	if (opt_rx && setsockopt(fd, SOL_TLS, TLS_RX, crypto_info,
				 sizeof(*crypto_info))) {
		perror("    Can't set RX");
		return 1;
	}
	END_T(3);

	return 0;
}

static int child_proc(void)
{
	struct timespec start_delay = { 0, 5 * 1000 * 1000};
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	const unsigned int conn_wheel_sz = opt_keep + 1;
	struct timespec delay = {
		.tv_sec		= opt_sleep / (1000 * 1000),
		.tv_nsec	= (opt_sleep * 1000) % (1000 * 1000 * 1000),
	};
	clock_t start, end;
	unsigned int i;
	int *fds;
	int err;

	/* Try to let the spawning continue before we hog the CPU */
	nanosleep(&start_delay, NULL);

	crypto_info.info.version = opt_tls_version;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

	memset(crypto_info.iv, 0x11, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memset(crypto_info.rec_seq, 0, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memset(crypto_info.key, 0x22, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memset(crypto_info.salt, 0x33, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	err = ls_sched_set_rt();
	if (err)
		return err;

	fds = malloc(conn_wheel_sz * sizeof(int));
	if (!fds) {
		err_msg("    Out of memory.\n");
		return 1;
	}
	for (i = 0; i < conn_wheel_sz; i++)
		fds[i] = -1;

	while (opt_conns--) {
		i = opt_conns % conn_wheel_sz;

		if (fds[i] >= 0)
			close(fds[i]);

		start = clock();

		fds[i] = socket(ai->ai_family, ai->ai_socktype,
				ai->ai_protocol);
		if (fds[i] < 0) {
			perror("    Failed to socket.\n");
			break;
		}

		if (do_tls_conn(fds[i], &crypto_info))
			break;

		END_T(4);

		if (opt_sleep)
			nanosleep(&delay, NULL);
	}

	for (i = 0; i < conn_wheel_sz; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	free(fds);

	sem_wait(&shared->sem);
	for (i = 0; i < ARRAY_SIZE(max_t); i++)
		if (shared->max_t[i] < max_t[i])
			shared->max_t[i] = max_t[i];
	sem_post(&shared->sem);

	return opt_conns > -1;
}

static void usage(int exit_code)
{
	fprintf(stderr,
		"Usage: %s OPTIONS -s <host> -p <port>\n"
		"\n"
		"This program implements kTLS connection stress test.\n"
		"It uses multiple processes to connect to a server\n"
		"(e.g. tcp_acceptor) and install TLS state on the socket.\n"
		"No data is ever exchanged.\n"
		"\n"
		"\t-s|--server     <host> server name or address to connect to\n"
		"\t-p|--port       <port> port or service name to connect to\n"
		"    OPTIONS:\n"
		"\t-n|--n-procs    <count> number of processes to spawn\n"
		"\t-c|--connections <count> number of connections per process\n"
		"\t-k|--keep-conn  <count> number of connections to kept open per process\n"
		"\t-d|--direction  [rx|tx|both] direction of TLS state to be installed\n"
		"\t-t|--sleep      <usecs> sleep time between every -c connections\n"
		"\t-4|--ipv4-only  force the use of IPv4\n"
		"\t-6|--ipv6-only  force the use of IPv6\n"
		"\t-T|--tls-version [1.2|1.3] choose TLS version\n"
		"\t-h|--help       print help and exit\n"
		"", bin);
	exit(exit_code);
}

int main(int argc, char *const *argv)
{
	static const struct option options[] = {
		{ "server",	required_argument,	NULL,	's' },
		{ "port",	required_argument,	NULL,	'p' },
		{ "n-procs",	required_argument,	NULL,	'n' },
		{ "keep-conn",	required_argument,	NULL,	'k' },
		{ "connections", required_argument,	NULL,	'c' },
		{ "direction",	required_argument,	NULL,	'd' },
		{ "sleep",	required_argument,	NULL,	't' },
		{ "ipv4-only",	no_argument,		NULL,	'4' },
		{ "ipv6-only",	no_argument,		NULL,	'6' },
		{ "tls-version", required_argument,	NULL,	'T' },
		{ "help",	no_argument,		NULL,	'h' },
		{ 0 }
	};
	static struct addrinfo *addrinfo, hints;
	const char *host = NULL, *port = NULL;
	int opt_n_procs = 1, n_spawned;
	int opt, ret, fd, status, i;
	bool bad = false;
	char *endptr;
	int *pids;

	bin = argv[0];

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "46hs:p:n:k:c:d:t:T:",
				  options, NULL)) >= 0) {
		switch (opt) {
		case '4':
		case '6':
			if (hints.ai_family)
				return err_ret(1, "family already set\n");
			hints.ai_family = opt == '4' ? AF_INET : AF_INET6;
			break;
		case 's':
			host = argv[optind - 1];
			break;
		case 'p':
			port = argv[optind - 1];
			break;
		case 'n':
			opt_n_procs = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse n procs '%s'\n",
					       argv[optind - 1]);
			break;
		case 'c':
			opt_conns = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse connections '%s'\n",
					       argv[optind - 1]);
			break;
		case 'k':
			opt_keep = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse keep connections '%s'\n",
					       argv[optind - 1]);
			break;
		case 'd':
			opt_rx = !strcmp(argv[optind - 1], "rx") ||
				!strcmp(argv[optind - 1], "both");
			opt_tx = !strcmp(argv[optind - 1], "tx") ||
				!strcmp(argv[optind - 1], "both");

			if (!opt_rx && !opt_tx)
				return err_ret(1,
					       "can't parse direction '%s'\n",
					       argv[optind - 1]);
			break;
		case 't':
			opt_sleep = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse sleep '%s'\n",
					       argv[optind - 1]);
			break;
		case 'T':
			if (!strcmp(argv[optind - 1], "1.2"))
				opt_tls_version = TLS_1_2_VERSION;
			else if (!strcmp(argv[optind - 1], "1.3"))
				opt_tls_version = TLS_1_3_VERSION;
			else
				return err_ret(1,
					       "can't parse TLS version '%s'\n",
					       argv[optind - 1]);
			break;
		case 'h':
			usage(0);
			break;
		default:
			err_msg("unrecognized option '%s'\n", argv[optind - 1]);
			usage(1);
		}
	}

	if (!host)
		return err_ret(2, "server address not specified\n");
	if (!port)
		return err_ret(2, "port/service name not specified\n");

	/* Resolved destination */
	ret = getaddrinfo(host, port, &hints, &addrinfo);
	if (ret) {
		err_msg("can't resolve the server/port: %s\n",
			gai_strerror(ret));
		return 1;
	}

	/* Find the destination to use */
	fd = -1;
	for (ai = addrinfo; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		if (connect(fd, ai->ai_addr, ai->ai_addrlen)) {
			close(fd);
			continue;
		}

		close(fd);
		break;
	}
	if (!ai) {
		err_msg("unable to connect to the specified server\n");
		ret = 2;
		goto exit_free_addr;
	}

	/* Create a semaphore for stdout access */
	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_SHARED, 0, 0);
	if (!shared) {
		err_msg("unable to map memory for semaphore: %s\n",
			strerror(errno));
		ret = 3;
		goto exit_free_addr;
	}
	memset(shared, 0, sizeof(*shared));
	if (sem_init(&shared->sem, 1, 1)) {
		err_msg("unable to init semaphore: %s\n", strerror(errno));
		ret = 4;
		goto exit_free_sem;
	}

	pids = calloc(opt_n_procs, sizeof(*pids));
	if (!pids) {
		ret = 5;
		goto exit_free_sem;
	}

	for (i = 0; i < opt_n_procs; i++) {
		pids[i] = fork();
		if (!pids[i]) {
			ret = child_proc();
			goto exit_free_pids;
		} else if (pids[i] < 0) {
			err_msg("failed to spawn process %d: %s\n",
				i, strerror(errno));
			bad = true;
			break;
		}
	}
	n_spawned = i;


	for (i = 0; i < n_spawned; i++) {
		wait(&status);
		bad |= status;
	}

	if (!bad) {
		printf("{ \"usec_max_connect\" : %ld, ",
		       clock_to_us(shared->max_t[0]));
		printf("\"usec_max_ktls_ulp\" : %ld, ",
		       clock_to_us(shared->max_t[1]));
		printf("\"usec_max_ktls_tx\" : %ld, ",
		       clock_to_us(shared->max_t[2]));
		printf("\"usec_max_ktls_rx\" : %ld, ",
		       clock_to_us(shared->max_t[3]));
		printf("\"usec_max_total\" : %ld }\n",
		       clock_to_us(shared->max_t[4]));
	} else {
		printf("null\n");
	}

	ret = bad * 16;
exit_free_pids:
	free(pids);
exit_free_sem:
	munmap(shared, sizeof(*shared));
exit_free_addr:
	freeaddrinfo(addrinfo);
	return ret;
}
