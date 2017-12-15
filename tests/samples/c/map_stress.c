#include <bpf.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define err(msg, arg...)	\
	fprintf(stderr, "Error: %s: " msg, __func__, arg)
#define warn(msg, arg...)	\
	fprintf(stderr, "Warning: %s: " msg, __func__, arg)
#define dbg(msg, arg...)	\
	fprintf(stdout, "%s: " msg, __func__, arg)

enum act {
	ACT_GET_FIRST,
	ACT_GET_NEXT_VALID,
	ACT_GET_NEXT_NOEXIST,
	ACT_GET_NEXT_LAST,
	ACT_UPDATE_EXIST_ANY,
	ACT_UPDATE_EXIST_NOEXIST,
	ACT_UPDATE_EXIST_EXIST,
	ACT_UPDATE_NOEXIST_ANY,
	ACT_UPDATE_NOEXIST_NOEXIST,
	ACT_UPDATE_NOEXIST_EXIST,
	ACT_LOOKUP_EXIST,
	ACT_LOOKUP_NOEXIST,
	ACT_DELETE_EXIST,
	ACT_DELETE_NOEXIST,
	ACT_WALK,
	NUM_ACTS,
	ACT_UPDATE_FULL,
};

struct thread {
	pthread_t thread;
	unsigned int id;
	struct random_data r;
	char r_state[128];
	int fd;
	struct bpf_map_info info;
};

static unsigned int max_entries;

static int errcnt;
static unsigned long int n_rep;

static unsigned int rand_uint(struct thread *this, unsigned int max)
{
	int val;

	random_r(&this->r, &val);
	return val % max;
}

static unsigned int get_key(struct thread *this)
{
	return rand_uint(this, max_entries);
}

static unsigned long long int get_value(struct thread *this)
{
	int tmp[2];

	random_r(&this->r, &tmp[0]);
	random_r(&this->r, &tmp[1]);

	return (unsigned long long int)tmp[0] << 32 | tmp[1];
}

static int do_get_next(struct thread *this)
{
	char nextkey[this->info.key_size];
	unsigned int key;

	key = get_key(this);

	return bpf_map_get_next_key(this->fd, &key, nextkey);
}

static int do_get_first(struct thread *this)
{
	char nextkey[this->info.key_size];

	return bpf_map_get_next_key(this->fd, NULL, nextkey);
}

static int do_update(struct thread *this)
{
	unsigned long long int value;
	unsigned int key;

	key = get_key(this);
	value = get_value(this);

	return bpf_map_update_elem(this->fd, &key, &value, BPF_ANY);
}

static int do_lookup(struct thread *this)
{
	unsigned long long int value;
	unsigned int key;

	key = get_key(this);

	return bpf_map_lookup_elem(this->fd, &key, &value);
}

static int do_delete(struct thread *this)
{
	unsigned int key;

	key = get_key(this);

	return bpf_map_delete_elem(this->fd, &key);
}

static int do_walk(struct thread *this)
{
	char nextkey[this->info.key_size];
	char key[this->info.key_size];
	int err;

	err = bpf_map_get_next_key(this->fd, NULL, nextkey);
	while (!err) {
		memcpy(key, nextkey, this->info.key_size);
		err = bpf_map_delete_elem(this->fd, &key);
	}

	return 0;
}

static int do_one(struct thread *this)
{
	int act;

	random_r(&this->r, &act);
	act %= NUM_ACTS;

	/* Limit the getnext's, they are slow.. */
	if (act < ACT_UPDATE_EXIST_ANY || act == ACT_WALK) {
		if (rand_uint(this, 7) < 5)
			return 0;
		if (act == ACT_WALK && rand_uint(this, 7) < 5)
			return 0;
	}

	switch (act) {
	case ACT_GET_FIRST:
		return do_get_first(this);
	case ACT_GET_NEXT_VALID:
	case ACT_GET_NEXT_NOEXIST:
	case ACT_GET_NEXT_LAST:
		return do_get_next(this);
	case ACT_UPDATE_EXIST_ANY:
	case ACT_UPDATE_EXIST_NOEXIST:
	case ACT_UPDATE_EXIST_EXIST:
	case ACT_UPDATE_NOEXIST_ANY:
	case ACT_UPDATE_NOEXIST_NOEXIST:
	case ACT_UPDATE_NOEXIST_EXIST:
		return do_update(this);
	case ACT_LOOKUP_EXIST:
	case ACT_LOOKUP_NOEXIST:
		return do_lookup(this);
	case ACT_DELETE_EXIST:
	case ACT_DELETE_NOEXIST:
		return do_delete(this);
	case ACT_WALK:
		return do_walk(this);
	default:
		return 0;
	}
}

static void *thread_main(void *arg)
{
	__u32 info_len = sizeof(struct bpf_map_info);
	struct thread *this = arg;
	unsigned int i;
	int err;

	if (initstate_r(this->thread, this->r_state, sizeof(this->r_state),
			&this->r)) {
		err("can't init random: %s\n", strerror(errno));
		goto err_cnt;
	}

	this->fd = bpf_map_get_fd_by_id(this->id);
	if (this->fd < 0) {
		err("can't open FD: %s\n", strerror(errno));
		goto err_cnt;
	}

	memset(&this->info, 0, sizeof(this->info));
	err = bpf_obj_get_info_by_fd(this->fd, &this->info, &info_len);
	if (err) {
		err("can't get info: %s\n", strerror(errno));
		goto err_cnt;
	}

	for (i = 0; i < n_rep; i++) {
		do_one(this);
		if (!(i % 128))
			dbg("Thread %lx making progress %d/%ld...\n",
			    this->thread, i, n_rep);
	}

	close(this->fd);

	return NULL;

err_cnt:
	errcnt++;
	return NULL;
}

static void usage(char *binname, int retcode)
{
	printf("Usage: %s <map_id> <n_threads> <n_rep> <max_key>\n",
	       binname);
	exit(retcode);
	return;
}

int main(int argc, char **argv)
{
	unsigned long id, num_threads;
	struct thread *threads;
	unsigned int i;
	char *endptr;
	int err;

	if (argc != 5)
		usage(argv[0], 1);

	id = strtoul(argv[1], &endptr, 0);
	if (*endptr) {
		err("can't parse %s as ID", argv[1]);
		return 1;
	}
	num_threads = strtoul(argv[2], &endptr, 0);
	if (*endptr) {
		err("can't parse %s as num_threads", argv[2]);
		return 1;
	}
	n_rep = strtoul(argv[3], &endptr, 0);
	if (*endptr) {
		err("can't parse %s as n_rep", argv[3]);
		return 1;
	}
	max_entries = strtoul(argv[4], &endptr, 0);
	if (*endptr) {
		err("can't parse %s as max_entries", argv[4]);
		return 1;
	}

	threads = calloc(num_threads, sizeof(*threads));

	for (i = 0; i < num_threads; i++) {
		threads[i].id = id;

		err = pthread_create(&threads[i].thread, NULL, thread_main,
				     (void *)&threads[i]);
		if (err) {
			err("thread creation failed for thread %d\n", i);
			num_threads = i;
			break;
		}
	}

	for (i = 0; i < num_threads; i++)
		pthread_join(threads[i].thread, NULL);

	free(threads);

	return !!errcnt;
}
