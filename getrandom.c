/*
 * Copyright (C) 2016 Etienne Champetier <champetier.etienne@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ERROR_EXIT(fmt, ...) do { \
		fprintf(stderr, fmt, ## __VA_ARGS__); \
		return EXIT_FAILURE; \
	} while (0)

static int usage(char *name)
{
	fprintf(stderr, "Usage: %s <nb>\n", name);
	fprintf(stderr, " => return <nb> bytes from getrandom()\n");
	return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
		return usage(argv[0]);

	if (isatty(STDOUT_FILENO))
		ERROR_EXIT("Not outputting random to a tty\n");

	int nbtot = atoi(argv[1]);
	if (nbtot < 1)
		ERROR_EXIT("Invalid <nb> param (must be > 0)\n");

	char buf[256];
	int len = sizeof(buf);
	while (nbtot > 0) {
		if (nbtot <= sizeof(buf))
			len = nbtot;
		if (syscall(SYS_getrandom, buf, len, 0) == -1)
			ERROR_EXIT("getrandom() failed: %m\n");
		if (write(STDOUT_FILENO, buf, len) != len)
			ERROR_EXIT("write() failed: %m\n");
		nbtot -= sizeof(buf);
	}

	return 0;
}
