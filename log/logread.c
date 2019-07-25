/*
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <time.h>
#include <regex.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include <libubox/ustream.h>
#include <libubox/blobmsg_json.h>
#include <libubox/usock.h>
#include <libubox/uloop.h>
#include "libubus.h"
#include "syslog.h"

#define LOGD_CONNECT_RETRY	10

enum {
	LOG_STDOUT,
	LOG_FILE,
	LOG_NET,
};

enum {
	LOG_MSG,
	LOG_ID,
	LOG_PRIO,
	LOG_SOURCE,
	LOG_TIME,
	__LOG_MAX
};

static const struct blobmsg_policy log_policy[] = {
	[LOG_MSG] = { .name = "msg", .type = BLOBMSG_TYPE_STRING },
	[LOG_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[LOG_PRIO] = { .name = "priority", .type = BLOBMSG_TYPE_INT32 },
	[LOG_SOURCE] = { .name = "source", .type = BLOBMSG_TYPE_INT32 },
	[LOG_TIME] = { .name = "time", .type = BLOBMSG_TYPE_INT64 },
};

static struct uloop_timeout retry;
static struct uloop_fd sender;
static regex_t regexp_preg;
static const char *log_file, *log_ip, *log_port, *log_prefix, *pid_file, *hostname, *regexp_pattern;
static int log_type = LOG_STDOUT;
static int log_size, log_udp, log_follow, log_trailer_null = 0;
static int log_timestamp;
static int logd_conn_tries = LOGD_CONNECT_RETRY;
static int facility_include;
static int facility_exclude;

/* check for facility filter; return 0 if message shall be dropped */
static int check_facility_filter(int f)
{
	if (facility_include)
		return !!(facility_include & (1 << f));
	if (facility_exclude)
		return !(facility_exclude & (1 << f));
	return 1;
}

static const char* getcodetext(int value, CODE *codetable) {
	CODE *i;

	if (value >= 0)
		for (i = codetable; i->c_val != -1; i++)
			if (i->c_val == value)
				return (i->c_name);
	return "<unknown>";
};

static void log_handle_reconnect(struct uloop_timeout *timeout)
{
	sender.fd = usock((log_udp) ? (USOCK_UDP) : (USOCK_TCP), log_ip, log_port);
	if (sender.fd < 0) {
		fprintf(stderr, "failed to connect: %m\n");
		uloop_timeout_set(&retry, 1000);
	} else {
		uloop_fd_add(&sender, ULOOP_READ);
		syslog(LOG_INFO, "Logread connected to %s:%s\n", log_ip, log_port);
	}
}

static void log_handle_fd(struct uloop_fd *u, unsigned int events)
{
	if (u->eof) {
		uloop_fd_delete(u);
		close(sender.fd);
		sender.fd = -1;
		uloop_timeout_set(&retry, 1000);
	}
}

static int log_notify(struct blob_attr *msg)
{
	struct blob_attr *tb[__LOG_MAX];
	struct stat s;
	char buf[LOG_LINE_SIZE + 128];
	char buf_ts[32];
	uint32_t p;
	time_t t;
	uint32_t t_ms = 0;
	char *c, *m;
	int ret = 0;

	if (sender.fd < 0)
		return 0;

	blobmsg_parse(log_policy, ARRAY_SIZE(log_policy), tb, blob_data(msg), blob_len(msg));
	if (!tb[LOG_ID] || !tb[LOG_PRIO] || !tb[LOG_SOURCE] || !tb[LOG_TIME] || !tb[LOG_MSG])
		return 1;

	if ((log_type == LOG_FILE) && log_size && (!stat(log_file, &s)) && (s.st_size > log_size)) {
		char *old = malloc(strlen(log_file) + 5);

		close(sender.fd);
		if (old) {
			sprintf(old, "%s.old", log_file);
			rename(log_file, old);
			free(old);
		}
		sender.fd = open(log_file, O_CREAT | O_WRONLY | O_APPEND, 0600);
		if (sender.fd < 0) {
			fprintf(stderr, "failed to open %s: %m\n", log_file);
			exit(-1);
		}
	}
	p = blobmsg_get_u32(tb[LOG_PRIO]);

	if (!check_facility_filter(LOG_FAC(p)))
			return 0;

	m = blobmsg_get_string(tb[LOG_MSG]);
	if (regexp_pattern &&
	    regexec(&regexp_preg, m, 0, NULL, 0) == REG_NOMATCH)
		return 0;
	t = blobmsg_get_u64(tb[LOG_TIME]) / 1000;
	if (log_timestamp) {
		t_ms = blobmsg_get_u64(tb[LOG_TIME]) % 1000;
		snprintf(buf_ts, sizeof(buf_ts), "[%lu.%03u] ",
				(unsigned long)t, t_ms);
	}
	c = ctime(&t);
	c[strlen(c) - 1] = '\0';

	if (log_type == LOG_NET) {
		int err;

		snprintf(buf, sizeof(buf), "<%u>", p);
		strncat(buf, c + 4, 16);
		if (log_timestamp) {
			strncat(buf, buf_ts, sizeof(buf) - strlen(buf) - 1);
		}
		if (hostname) {
			strncat(buf, hostname, sizeof(buf) - strlen(buf) - 1);
			strncat(buf, " ", sizeof(buf) - strlen(buf) - 1);
		}
		if (log_prefix) {
			strncat(buf, log_prefix, sizeof(buf) - strlen(buf) - 1);
			strncat(buf, ": ", sizeof(buf) - strlen(buf) - 1);
		}
		if (blobmsg_get_u32(tb[LOG_SOURCE]) == SOURCE_KLOG)
			strncat(buf, "kernel: ", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, m, sizeof(buf) - strlen(buf) - 1);
		if (log_udp)
			err = write(sender.fd, buf, strlen(buf));
		else {
			size_t buflen = strlen(buf);
			if (!log_trailer_null)
				buf[buflen] = '\n';
			err = send(sender.fd, buf, buflen + 1, 0);
		}

		if (err < 0) {
			syslog(LOG_INFO, "failed to send log data to %s:%s via %s\n",
				log_ip, log_port, (log_udp) ? ("udp") : ("tcp"));
			uloop_fd_delete(&sender);
			close(sender.fd);
			sender.fd = -1;
			uloop_timeout_set(&retry, 1000);
		}
	} else {
		snprintf(buf, sizeof(buf), "%s %s%s.%s%s %s\n",
			c, log_timestamp ? buf_ts : "",
			getcodetext(LOG_FAC(p) << 3, facilitynames),
			getcodetext(LOG_PRI(p), prioritynames),
			(blobmsg_get_u32(tb[LOG_SOURCE])) ? ("") : (" kernel:"), m);
		ret = write(sender.fd, buf, strlen(buf));
	}

	if (log_type == LOG_FILE)
		fsync(sender.fd);

	return ret;
}

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"    -s <path>		Path to ubus socket\n"
		"    -l	<count>		Got only the last 'count' messages\n"
		"    -e	<pattern>	Filter messages with a regexp\n"
		"    -r	<server> <port>	Stream message to a server\n"
		"    -F	<file>		Log file\n"
		"    -S	<bytes>		Log size\n"
		"    -p	<file>		PID file\n"
		"    -h	<hostname>	Add hostname to the message\n"
		"    -P	<prefix>	Prefix custom text to streamed messages\n"
		"    -z	<facility>	handle only messages with given facility (0-23), repeatable\n"
		"    -Z	<facility>	ignore messages with given facility (0-23), repeatable\n"
		"    -f			Follow log messages\n"
		"    -u			Use UDP as the protocol\n"
		"    -t			Add an extra timestamp\n"
		"    -0			Use \\0 instead of \\n as trailer when using TCP\n"
		"\n", prog);
	return 1;
}

static void logread_fd_data_cb(struct ustream *s, int bytes)
{
	while (true) {
		struct blob_attr *a;
		int len, cur_len;

		a = (void*) ustream_get_read_buf(s, &len);
		if (len < sizeof(*a))
			break;

		cur_len = blob_len(a) + sizeof(*a);
		if (len < cur_len)
			break;

		log_notify(a);
		ustream_consume(s, cur_len);
	}
}

static void logread_fd_state_cb(struct ustream *s)
{
	if (log_follow)
		logd_conn_tries = LOGD_CONNECT_RETRY;
	uloop_end();
}

static void logread_fd_cb(struct ubus_request *req, int fd)
{
	static struct ustream_fd test_fd;

	memset(&test_fd, 0, sizeof(test_fd));

	test_fd.stream.notify_read = logread_fd_data_cb;
	test_fd.stream.notify_state = logread_fd_state_cb;
	ustream_fd_init(&test_fd, fd);
}

static void logread_setup_output(void)
{
	if (sender.fd || sender.cb)
		return;

	if (log_ip && log_port) {
		openlog("logread", LOG_PID, LOG_DAEMON);
		log_type = LOG_NET;
		sender.cb = log_handle_fd;
		retry.cb = log_handle_reconnect;
		uloop_timeout_set(&retry, 1000);
	} else if (log_file) {
		log_type = LOG_FILE;
		sender.fd = open(log_file, O_CREAT | O_WRONLY| O_APPEND, 0600);
		if (sender.fd < 0) {
			fprintf(stderr, "failed to open %s: %m\n", log_file);
			exit(-1);
		}
	} else {
		sender.fd = STDOUT_FILENO;
	}
}

int main(int argc, char **argv)
{
	struct ubus_context *ctx;
	uint32_t id;
	const char *ubus_socket = NULL;
	int ch, ret, lines = 0;
	static struct blob_buf b;

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "u0fcs:l:z:Z:r:F:p:S:P:h:e:t")) != -1) {
		switch (ch) {
		case 'u':
			log_udp = 1;
			break;
		case '0':
			log_trailer_null = 1;
			break;
		case 's':
			ubus_socket = optarg;
			break;
		case 'r':
			log_ip = optarg++;
			log_port = argv[optind++];
			break;
		case 'F':
			log_file = optarg;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'P':
			log_prefix = optarg;
			break;
		case 'f':
			log_follow = 1;
			break;
		case 'l':
			lines = atoi(optarg);
			break;
		case 'z':
			id = strtoul(optarg, NULL, 0) & 0x1f;
			facility_include |= (1 << id);
			break;
		case 'Z':
			id = strtoul(optarg, NULL, 0) & 0x1f;
			facility_exclude |= (1 << id);
			break;
		case 'S':
			log_size = atoi(optarg);
			if (log_size < 1)
				log_size = 1;
			log_size *= 1024;
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'e':
			if (!regcomp(&regexp_preg, optarg, REG_NOSUB)) {
				regexp_pattern = optarg;
			}
			break;
		case 't':
			log_timestamp = 1;
			break;
		default:
			return usage(*argv);
		}
	}
	uloop_init();

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}
	ubus_add_uloop(ctx);

	if (log_follow && pid_file) {
		FILE *fp = fopen(pid_file, "w+");
		if (fp) {
			fprintf(fp, "%d", getpid());
			fclose(fp);
		}
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "stream", 1);
	blobmsg_add_u8(&b, "oneshot", !log_follow);
	if (lines)
		blobmsg_add_u32(&b, "lines", lines);
	else if (log_follow)
		blobmsg_add_u32(&b, "lines", 0);

	/* ugly ugly ugly ... we need a real reconnect logic */
	do {
		struct ubus_request req = { 0 };

		ret = ubus_lookup_id(ctx, "log", &id);
		if (ret) {
			fprintf(stderr, "Failed to find log object: %s\n", ubus_strerror(ret));
			sleep(1);
			continue;
		}
		logd_conn_tries = 0;
		logread_setup_output();

		ubus_invoke_async(ctx, id, "read", b.head, &req);
		req.fd_cb = logread_fd_cb;
		ubus_complete_request_async(ctx, &req);

		uloop_run();

	} while (logd_conn_tries--);

	ubus_free(ctx);
	uloop_done();

	if (log_follow && pid_file)
		unlink(pid_file);

	return ret;
}
