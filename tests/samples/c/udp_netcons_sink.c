#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>

int main(int argc, const char **argv)
{
	struct sched_param sched_param = { .sched_priority = 50, };
	struct sockaddr_in addr = {};
	socklen_t addrlen = sizeof(addr);
	int sock, ofile;
	char buf[1024];
	int opt;
	int n;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <port> <outfile>\n", argv[0]);
		return 1;
	}
	close(2);
	close(1);
	close(0);

	assert(!sched_setscheduler(0, SCHED_FIFO, &sched_param));

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assert(sock >= 0);
	ofile = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY, 0666);
	assert(ofile >= 0);

	opt = 1;
	assert(!setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)));
	assert(!setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)));
	opt = 16777216;
	assert(!setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[1]));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	assert(!bind(sock, (void *)&addr, sizeof(addr)));

	n = recvfrom(sock, buf, sizeof(buf), 0, (void *)&addr, &addrlen);
	assert(n > 0);
	assert(write(ofile, buf, n) == n);

	assert(!connect(sock, (void *)&addr, sizeof(addr)));

	while (1) {
		n = read(sock, buf, sizeof(buf));
		assert(n > 0);
		assert(write(ofile, buf, n) == n);
	}

	close(sock);
	close(ofile);

	return 0;
}
