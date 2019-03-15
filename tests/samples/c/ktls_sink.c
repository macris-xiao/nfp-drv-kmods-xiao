// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "lib/samples.h"

static size_t opt_read_size;
static int opt_read_ival;
static unsigned long long opt_sleep_len;
static unsigned int opt_tls_version = TLS_1_2_VERSION;
static const char *bin;
static struct addrinfo *addrinfo;

static int setup_ktls(int fd)
{
	struct tls12_crypto_info_aes_gcm_128 crypto_info;

	if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")))
		return err_ret(1, "can't enable TLS ulp: %s\n",
			       strerror(errno));

	crypto_info.info.version = opt_tls_version;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

	memset(crypto_info.iv, 0x11, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memset(crypto_info.rec_seq, 0, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memset(crypto_info.key, 0x22, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memset(crypto_info.salt, 0x33, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	if (setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)))
		return err_ret(1, "can't enable TLS RX crypto: %s\n",
			       strerror(errno));

	return 0;
}

static void *client_thread(void *arg)
{
	int fd = (unsigned long)arg;
	int next_sleep = 0;
	char start = 0;
	char *buf;

	if (setup_ktls(fd))
		goto exit_close_sock;

	/* let the client know we are ready */
	if (send(fd, &start, sizeof(start), MSG_EOR) != sizeof(start)) {
		err_msg("start write failed: %s\n", strerror(errno));
		goto exit_close_sock;
	}

	buf = malloc(opt_read_size);
	if (!buf) {
		err_msg("read buffer allocation failed\n");
		goto exit_close_sock;
	}

	do {
		ssize_t res;

		res = read(fd, buf, opt_read_size);
		if (res < 0) {
			err_msg("read failed: %s\n", strerror(errno));
			goto exit_free_buf;
		}

		if (!res)
			break;

		if (++next_sleep == opt_read_ival) {
			struct timespec delay = { 0, opt_sleep_len * 1000};

			nanosleep(&delay, NULL);
			next_sleep = 0;
		}
	} while (true);

exit_free_buf:
	free(buf);
exit_close_sock:
	close(fd);
	return NULL;
}

static int ktls_sink_run(void)
{
	pthread_attr_t attr;
	int ret, err, fd;

	signal(SIGPIPE, SIG_IGN);

	fd = ls_socket_tcp_listen(addrinfo, 1000);
	freeaddrinfo(addrinfo);
	if (fd < 0)
		return -fd;

	err = ls_socket_set_reuse_opts(fd);
	if (err) {
		ret = err_ret(-err, "write buffer allocation failed\n");
		goto exit_close_sock;
	}

	if (pthread_attr_init(&attr)) {
		ret = err_ret(8, "thread attr init failed: %s\n",
			      strerror(errno));
		goto exit_close_sock;
	}

	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
		ret = err_ret(8, "thread attr set detached failed: %s\n",
			      strerror(errno));
		goto exit_free_attr;
	}

	for (;;) {
		pthread_t thread;
		int client;

		client = accept(fd, NULL, NULL);
		if (client < 0) {
			ret = err_ret(7, "accept failed: %s\n",
				      strerror(errno));
			goto exit_free_attr;
		}

		if (pthread_create(&thread, &attr, client_thread,
				   (void *)(long unsigned)client)) {
			ret = err_ret(-err, "thread creation failed: %s\n",
				      strerror(errno));
			goto exit_free_attr;
		}
	}

exit_free_attr:
	if (pthread_attr_destroy(&attr))
		err_msg("thread attr destroy failed: %s\n", strerror(errno));
exit_close_sock:
	close(fd);
	return ret;
}

static void usage(int exit_code)
{
	fprintf(stderr,
		"Usage: %s OPTIONS -p <port>\n"
		"\t-p|--port       <port> port or service name to connect to\n"
		"    OPTIONS:\n"
		"\t-r|--read-size <bytes> amount of data per write\n"
		"\t-i|--read-ival <count> number of writes per sleep period\n"
		"\t-t|--read-len  <usecs> sleep time in usec\n"
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
		{ "port",	required_argument,	NULL,	'p' },
		{ "read-size",	required_argument,	NULL,	'r' },
		{ "read-ival",	required_argument,	NULL,	'i' },
		{ "read-len",	required_argument,	NULL,	't' },
		{ "ipv4-only",	no_argument,		NULL,	'4' },
		{ "ipv6-only",	no_argument,		NULL,	'6' },
		{ "tls-version", required_argument,	NULL,	'T' },
		{ "help",	no_argument,		NULL,	'h' },
		{ 0 }
	};
	const char *port = NULL;
	struct addrinfo hints;
	int err, opt;
	char *endptr;

	bin = argv[0];

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "46hp:r:i:t:T:",
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
		case 'r':
			opt_read_size = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse read size '%s'\n",
					       argv[optind - 1]);
			break;
		case 'i':
			opt_read_ival = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse read ival '%s'\n",
					       argv[optind - 1]);
			break;
		case 't':
			opt_sleep_len = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse sleep length '%s'\n",
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

	if (!port)
		return err_ret(2, "port/service name not specified\n");
	if (!opt_read_size)
		return err_ret(2, "read size not specified\n");

	/* Resolved destination */
	err = getaddrinfo(NULL, port, &hints, &addrinfo);
	if (err) {
		err_msg("can't resolve the port: %s\n",	gai_strerror(err));
		return 1;
	}

	return ktls_sink_run();
}
