// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
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

static size_t opt_length, opt_write_size;
static int opt_write_ival;
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

	if (setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)))
		return err_ret(1, "can't enable TLS TX crypto: %s\n",
			       strerror(errno));

	return 0;
}

static int ktls_source_run(void)
{
	const struct timespec delay = {
		.tv_sec		= opt_sleep_len / (1000 * 1000),
		.tv_nsec	= (opt_sleep_len * 1000) % (1000 * 1000 * 1000),
	};
	int next_sleep = 0;
	size_t todo;
	int ret, fd;
	char start;
	char *buf;

	signal(SIGPIPE, SIG_IGN);

	fd = ls_socket_tcp_connect(addrinfo);
	freeaddrinfo(addrinfo);
	if (fd < 0)
		return -fd;

	ret = setup_ktls(fd);
	if (ret)
		goto exit_close_sock;

	buf = malloc(opt_write_size);
	if (!buf) {
		ret = err_ret(4, "write buffer allocation failed\n");
		goto exit_close_sock;
	}
	memset(buf, 0x1c, opt_write_size);

	/* wait for server to green light us */
	if (read(fd, &start, sizeof(start)) != sizeof(start)) {
		ret = err_ret(5, "start read failed: %s\n", strerror(errno));
		goto exit_free_buf;
	}

	todo = opt_length;
	do {
		ssize_t res, chunk;

		chunk = opt_write_size ?: todo;
		if ((size_t)chunk > todo)
			chunk = todo;

		res = write(fd, buf, chunk);
		if (res <= 0) {
			ret = err_ret(4, "write failed (%zd/%zd): %s\n",
				      opt_length - todo, opt_length,
				      strerror(errno));
			goto exit_free_buf;
		}

		todo -= res;
		if (!todo)
			break;

		if (++next_sleep == opt_write_ival) {
			struct timespec d = delay;

			nanosleep(&d, NULL);
			next_sleep = 0;
		}
	} while (true);

exit_free_buf:
	free(buf);
exit_close_sock:
	close(fd);
	return ret;
}

static void usage(int exit_code)
{
	fprintf(stderr,
		"Usage: %s OPTIONS -s <host> -p <port> -l <bytes>\n"
		"\t-s|--server     <host> server name or address to connect to\n"
		"\t-p|--port       <port> port or service name to connect to\n"
		"\t-l|--length     <bytes> number of bytes to send\n"
		"    OPTIONS:\n"
		"\t-w|--write-size <bytes> amount of data per write\n"
		"\t-i|--write-ival <count> number of writes per sleep period\n"
		"\t-t|--write-len  <usecs> sleep time in usec\n"
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
		{ "length",	required_argument,	NULL,	'l' },
		{ "write-size",	required_argument,	NULL,	'w' },
		{ "write-ival",	required_argument,	NULL,	'i' },
		{ "write-len",	required_argument,	NULL,	't' },
		{ "ipv4-only",	no_argument,		NULL,	'4' },
		{ "ipv6-only",	no_argument,		NULL,	'6' },
		{ "tls-version", required_argument,	NULL,	'T' },
		{ "help",	no_argument,		NULL,	'h' },
		{ 0 }
	};
	const char *host = NULL, *port = NULL;
	struct addrinfo hints;
	int err, opt;
	char *endptr;

	bin = argv[0];

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "46hs:p:l:w:i:t:T:",
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
		case 'l':
			opt_length = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1, "can't parse length '%s'\n",
					       argv[optind - 1]);
			break;
		case 'w':
			opt_write_size = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse write size '%s'\n",
					       argv[optind - 1]);
			break;
		case 'i':
			opt_write_ival = strtol(argv[optind - 1], &endptr, 0);
			if (*endptr)
				return err_ret(1,
					       "can't parse write ival '%s'\n",
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

	if (!host)
		return err_ret(2, "server address not specified\n");
	if (!port)
		return err_ret(2, "port/service name not specified\n");
	if (!opt_length)
		return err_ret(2, "transfer length not specified\n");

	/* Resolved destination */
	err = getaddrinfo(host, port, &hints, &addrinfo);
	if (err) {
		err_msg("can't resolve the server/port: %s\n",
			gai_strerror(err));
		return 1;
	}

	return ktls_source_run();
}
