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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include <libubox/blobmsg_json.h>
#include <libubox/usock.h>
#include <libubox/uloop.h>
#include "libubus.h"
#include "syslog.h"

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

static struct ubus_subscriber log_event;
static struct uloop_timeout retry;
static struct uloop_fd sender;
static const char *log_file, *log_ip, *log_port, *log_prefix, *pid_file, *hostname;
static int log_type = LOG_STDOUT;
static int log_size, log_udp;

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
		fprintf(stderr, "failed to connect: %s\n", strerror(errno));
		uloop_timeout_set(&retry, 1000);
	} else {
		uloop_fd_add(&sender, ULOOP_READ);
		syslog(0, "Logread connected to %s:%s\n", log_ip, log_port);
	}
}

static void log_handle_remove(struct ubus_context *ctx, struct ubus_subscriber *s,
			uint32_t id)
{
	fprintf(stderr, "Object %08x went away\n", id);
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

static int log_notify(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__LOG_MAX];
	struct stat s;
	char buf[512];
	uint32_t p;
	char *str;
	time_t t;
	char *c;

	if (sender.fd < 0)
		return 0;

	blobmsg_parse(log_policy, ARRAY_SIZE(log_policy), tb, blob_data(msg), blob_len(msg));
	if (!tb[LOG_ID] || !tb[LOG_PRIO] || !tb[LOG_SOURCE] || !tb[LOG_TIME])
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
//			fprintf(stderr, "failed to open %s: %s\n", log_file, strerror(errno));
			exit(-1);
		}
	}

	t = blobmsg_get_u64(tb[LOG_TIME]) / 1000;
	c = ctime(&t);
	p = blobmsg_get_u32(tb[LOG_PRIO]);
	c[strlen(c) - 1] = '\0';
	str = blobmsg_format_json(msg, true);
	if (log_type == LOG_NET) {
		int err;

		*buf = '\0';
		if (hostname)
			snprintf(buf, sizeof(buf), "%s ", hostname);
		if (log_prefix) {
			strncat(buf, log_prefix, sizeof(buf));
			strncat(buf, ": ", sizeof(buf));
		}
		if (blobmsg_get_u32(tb[LOG_SOURCE]) == SOURCE_KLOG)
			strncat(buf, "kernel: ", sizeof(buf));
		strncat(buf, method, sizeof(buf));
		if (log_udp)
			err = write(sender.fd, buf, strlen(buf));
		else
			err = send(sender.fd, buf, strlen(buf), 0);

		if (err < 0) {
			syslog(0, "failed to send log data to %s:%s via %s\n",
				log_ip, log_port, (log_udp) ? ("udp") : ("tcp"));
			uloop_fd_delete(&sender);
			close(sender.fd);
			sender.fd = -1;
			uloop_timeout_set(&retry, 1000);
		}
	} else {
		snprintf(buf, sizeof(buf), "%s %s.%s%s %s\n",
			c, getcodetext(LOG_FAC(p) << 3, facilitynames), getcodetext(LOG_PRI(p), prioritynames),
			(blobmsg_get_u32(tb[LOG_SOURCE])) ? ("") : (" kernel:"),
			method);
		write(sender.fd, buf, strlen(buf));
	}

	free(str);
	if (log_type == LOG_FILE)
		fsync(sender.fd);

	return 0;
}

static void follow_log(struct ubus_context *ctx, int id)
{
	FILE *fp;
	int ret;

	signal(SIGPIPE, SIG_IGN);

	if (pid_file) {
		fp = fopen(pid_file, "w+");
		if (fp) {
			fprintf(fp, "%d", getpid());
			fclose(fp);
		}
	}

	uloop_init();
	ubus_add_uloop(ctx);

	log_event.remove_cb = log_handle_remove;
	log_event.cb = log_notify;
	ret = ubus_register_subscriber(ctx, &log_event);
	if (ret)
		fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));

	ret = ubus_subscribe(ctx, &log_event, id);
	if (ret)
		fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));

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
			fprintf(stderr, "failed to open %s: %s\n", log_file, strerror(errno));
			exit(-1);
		}
	} else {
		sender.fd = STDOUT_FILENO;
	}

	uloop_run();
	ubus_free(ctx);
	uloop_done();
}

enum {
	READ_LINE,
	__READ_MAX
};



static const struct blobmsg_policy read_policy[] = {
	[READ_LINE] = { .name = "lines", .type = BLOBMSG_TYPE_ARRAY },
};

static void read_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *cur;
	struct blob_attr *_tb[__READ_MAX];
	time_t t;
	int rem;

	if (!msg)
		return;

	blobmsg_parse(read_policy, ARRAY_SIZE(read_policy), _tb, blob_data(msg), blob_len(msg));
	if (!_tb[READ_LINE])
		return;
	blobmsg_for_each_attr(cur, _tb[READ_LINE], rem) {
		struct blob_attr *tb[__LOG_MAX];
		uint32_t p;
		char *c;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;

		blobmsg_parse(log_policy, ARRAY_SIZE(log_policy), tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[LOG_MSG] || !tb[LOG_ID] || !tb[LOG_PRIO] || !tb[LOG_SOURCE] || !tb[LOG_TIME])
			continue;

		t = blobmsg_get_u64(tb[LOG_TIME]);
		p = blobmsg_get_u32(tb[LOG_PRIO]);
		c = ctime(&t);
		c[strlen(c) - 1] = '\0';

		printf("%s %s.%s%s %s\n",
			c, getcodetext(LOG_FAC(p) << 3, facilitynames), getcodetext(LOG_PRI(p), prioritynames),
			(blobmsg_get_u32(tb[LOG_SOURCE])) ? ("") : (" kernel:"),
			blobmsg_get_string(tb[LOG_MSG]));
	}
}

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"    -s <path>		Path to ubus socket\n"
		"    -l	<count>		Got only the last 'count' messages\n"
		"    -r	<server> <port>	Stream message to a server\n"
		"    -F	<file>		Log file\n"
		"    -S	<bytes>		Log size\n"
		"    -p	<file>		PID file\n"
		"    -h	<hostname>	Add hostname to the message\n"
		"    -P	<prefix>	Prefix custom text to streamed messages\n"
		"    -f			Follow log messages\n"
		"    -u			Use UDP as the protocol\n"
		"\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	struct ubus_context *ctx;
	uint32_t id;
	const char *ubus_socket = NULL;
	int ch, ret, subscribe = 0, lines = 0;
	static struct blob_buf b;

	while ((ch = getopt(argc, argv, "ufcs:l:r:F:p:S:P:h:")) != -1) {
		switch (ch) {
		case 'u':
			log_udp = 1;
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
			subscribe = 1;
			break;
		case 'l':
			lines = atoi(optarg);
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
		default:
			return usage(*argv);
		}
	}

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ret = ubus_lookup_id(ctx, "log", &id);
	if (ret)
		fprintf(stderr, "Failed to find log object: %s\n", ubus_strerror(ret));

	if (!subscribe || lines) {
		blob_buf_init(&b, 0);
		if (lines)
			blobmsg_add_u32(&b, "lines", lines);
		ubus_invoke(ctx, id, "read", b.head, read_cb, 0, 3000);
	}

	if (subscribe)
		follow_log(ctx, id);

	return 0;
}
