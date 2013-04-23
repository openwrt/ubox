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

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <values.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <glob.h>
#include <sys/utsname.h>

#define DEF_MOD_PATH "/lib/modules/%s/%s.ko"
static int insmod(char *module, const char *options)
{
	struct utsname ver;
	char path[256];
	void *data = 0;
	struct stat s;
	int fd, ret = -1;

	uname(&ver);
	snprintf(path, 256, DEF_MOD_PATH, ver.release, module);

	if (stat(path, &s)) {
		fprintf(stderr, "missing module %s\n", path);
		return ret;
	}

	fd = open(path, O_RDONLY);
	if (!fd) {
		fprintf(stderr, "cannot open %s\n", path);
		return ret;
	}

	data = malloc(s.st_size);
	if (read(fd, data, s.st_size) == s.st_size) {
		ret = syscall(__NR_init_module, data, s.st_size, options);
		if (ret)
			fprintf(stderr, "failed insert %s\n", module);
	} else {
		fprintf(stderr, "failed to read full module %s\n", path);
	}

	close(fd);
	free(data);

	return ret;
}

/*static void rmmod(char *module)
{
	syscall(__NR_delete_module, module, 0);
}*/

int main(int argc, char **argv)
{
	glob_t gl;
	int gl_flags = GLOB_NOESCAPE | GLOB_MARK;
	char *tmp = malloc(256);
	char *dir = "/etc/modules.d/*";

	if (argc > 1)
		dir = argv[1];

	syslog(0, "kmodloader: loading kernel modules from %s\n", dir);

	if (glob(dir, gl_flags, NULL, &gl) >= 0) {
		int j;

		for (j = 0; j < gl.gl_pathc; j++) {
			FILE *fp = fopen(gl.gl_pathv[j], "r");

			if (!fp) {
				fprintf(stderr, "failed to open %s\n", gl.gl_pathv[j]);
			} else {
				char mod[64];

				while (fgets(mod, 64, fp)) {
					mod[strlen(mod) - 1] = '\0';
					insmod(mod, "");
				}
				fclose(fp);
			}
		}
	}

	globfree(&gl);
	free(tmp);

	return 0;
}
