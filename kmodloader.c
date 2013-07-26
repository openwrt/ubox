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
#include <sys/mman.h>
#include <sys/utsname.h>

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
#include <elf.h>

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/utils.h>

#define DEF_MOD_PATH "/lib/modules/%s/"

enum {
	SCANNED,
	PROBE,
	LOADED,
	FAILED,
};

struct module {
	struct avl_node avl;

	char *name;
	char *depends;

	int size;
	int usage;
	int state;
};

static struct avl_tree modules;
static char *prefix = "";

static struct module *find_module(const char *name)
{
	struct module *m;
	return avl_find_element(&modules, name, m, avl);
}

static void free_modules(void)
{
	struct module *m, *tmp;

	avl_remove_all_elements(&modules, m, avl, tmp)
		free(m);
}

static char* get_module_path(char *name)
{
	static char path[256];
	struct utsname ver;
	struct stat s;
	char *t;

	if (!stat(name, &s))
		return name;

	uname(&ver);
	snprintf(path, 256, "%s" DEF_MOD_PATH "%s.ko", prefix, ver.release, name);

	if (!stat(path, &s))
		return path;

	t = name;
	while (t && *t) {
		if (*t == '_')
			*t = '-';
		t++;
	}

	snprintf(path, 256, "%s" DEF_MOD_PATH "%s.ko", prefix, ver.release, name);

	if (!stat(path, &s))
		return path;

	return NULL;
}

static char* get_module_name(char *path)
{
	static char name[32];
	char *t;

	strncpy(name, basename(path), sizeof(name));

	t = strstr(name, ".ko");
	if (t)
		*t = '\0';
	t = name;
	while (t && *t) {
		if (*t == '-')
			*t = '_';
		t++;
	}

	return name;
}

#if __WORDSIZE == 64
static int elf_find_section(char *map, const char *section, unsigned int *offset, unsigned int *size)
{
	const char *secnames;
	Elf64_Ehdr *e;
	Elf64_Shdr *sh;
	int i;

	e = (Elf64_Ehdr *) map;
	sh = (Elf64_Shdr *) (map + e->e_shoff);

	secnames = map + sh[e->e_shstrndx].sh_offset;
	for (i = 0; i < e->e_shnum; i++) {
		if (!strcmp(section, secnames + sh[i].sh_name)) {
			*size = sh[i].sh_size;
			*offset = sh[i].sh_offset;
			return 0;
		}
	}

	return -1;
}
#else
static int elf_find_section(char *map, const char *section, unsigned int *offset, unsigned int *size)
{
	const char *secnames;
	Elf32_Ehdr *e;
	Elf32_Shdr *sh;
	int i;

	e = (Elf32_Ehdr *) map;
	sh = (Elf32_Shdr *) (map + e->e_shoff);

	secnames = map + sh[e->e_shstrndx].sh_offset;
	for (i = 0; i < e->e_shnum; i++) {
		if (!strcmp(section, secnames + sh[i].sh_name)) {
			*size = sh[i].sh_size;
			*offset = sh[i].sh_offset;
			return 0;
		}
	}

	return -1;
}
#endif

static struct module *
alloc_module(const char *name, const char *depends, int size)
{
	struct module *m;
	char *_name, *_dep;

	m = calloc_a(sizeof(*m),
		&_name, strlen(name) + 1,
		&_dep, depends ? strlen(depends) + 1 : 0);
	if (!m)
		return NULL;

	m->avl.key = m->name = strcpy(_name, name);
	if (depends)
		m->depends = strcpy(_dep, depends);

	m->size = size;
	avl_insert(&modules, &m->avl);
	return m;
}

static int scan_loaded_modules(void)
{
	size_t buf_len = 0;
	char *buf = NULL;
	FILE *fp;

	fp = fopen("/proc/modules", "r");
	if (!fp) {
		fprintf(stderr, "failed to open /proc/modules\n");
		return -1;
	}

	while (getline(&buf, &buf_len, fp) > 0) {
		struct module m;
		struct module *n;

		m.name = strtok(buf, " ");
		m.size = atoi(strtok(NULL, " "));
		m.usage = atoi(strtok(NULL, " "));
		m.depends = strtok(NULL, " ");

		if (!m.name || !m.depends)
			continue;

		n = alloc_module(m.name, m.depends, m.size);
		n->usage = m.usage;
		n->state = LOADED;
	}
	free(buf);
	fclose(fp);

	return 0;
}

static struct module* get_module_info(const char *module, const char *name)
{
	int fd = open(module, O_RDONLY);
	unsigned int offset, size;
	char *map, *strings, *dep = NULL;
	struct module *m;
	struct stat s;

	if (!fd) {
		fprintf(stderr, "failed to open %s\n", module);
		return NULL;
	}

	if (fstat(fd, &s) == -1) {
		fprintf(stderr, "failed to stat %s\n", module);
		return NULL;
	}

	map = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "failed to mmap %s\n", module);
		return NULL;
	}

	if (elf_find_section(map, ".modinfo", &offset, &size)) {
		fprintf(stderr, "failed to load the .modinfo section from %s\n", module);
		return NULL;
	}

	strings = map + offset;
	while (strings && (strings < map + offset + size)) {
		char *sep;
		int len;

		while (!strings[0])
			strings++;
		sep = strstr(strings, "=");
		if (!sep)
			break;
		len = sep - strings;
		sep++;
		if (!strncmp(strings, "depends=", len + 1))
			dep = sep;
		strings = &sep[strlen(sep)];
	}

	m = alloc_module(name, dep, s.st_size);
	if (!m)
		return NULL;

	m->state = SCANNED;

	return m;
}

static int scan_module_folder(char *dir)
{
	int gl_flags = GLOB_NOESCAPE | GLOB_MARK;
	int j;
	glob_t gl;

	if (glob(dir, gl_flags, NULL, &gl) < 0)
		return -1;

	for (j = 0; j < gl.gl_pathc; j++) {
		char *name = get_module_name(gl.gl_pathv[j]);
		struct module *m;

		if (!name)
			continue;

		m = find_module(name);
		if (!m)
			get_module_info(gl.gl_pathv[j], name);
	}

	globfree(&gl);

	return 0;
}

static int print_modinfo(char *module)
{
	int fd = open(module, O_RDONLY);
	unsigned int offset, size;
	struct stat s;
	char *map, *strings;

	if (!fd) {
		fprintf(stderr, "failed to open %s\n", module);
		return -1;
	}

	if (fstat(fd, &s) == -1) {
		fprintf(stderr, "failed to stat %s\n", module);
		return -1;
	}

	map = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "failed to mmap %s\n", module);
		return -1;
	}

	if (elf_find_section(map, ".modinfo", &offset, &size)) {
		fprintf(stderr, "failed to load the .modinfo section from %s\n", module);
		return -1;
	}

	strings = map + offset;
	printf("module:\t\t%s\n", module);
	while (strings && (strings < map + offset + size)) {
		char *dup = NULL;
		char *sep;

		while (!strings[0])
			strings++;
		sep = strstr(strings, "=");
		if (!sep)
			break;
		dup = strndup(strings, sep - strings);
		sep++;
		if (strncmp(strings, "parm", 4)) {
			if (strlen(dup) < 7)
				printf("%s:\t\t%s\n",  dup, sep);
			else
				printf("%s:\t%s\n",  dup, sep);
		}
		strings = &sep[strlen(sep)];
		if (dup)
			free(dup);
	}

	return 0;
}

static int insert_module(char *path, const char *options)
{
	void *data = 0;
	struct stat s;
	int fd, ret = -1;

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
			fprintf(stderr, "failed to insert %s\n", path);
	} else {
		fprintf(stderr, "failed to read full module %s\n", path);
	}

	close(fd);
	free(data);

	return ret;
}

static int deps_available(struct module *m)
{
	char *deps = m->depends;
	char *comma;

	if (!strcmp(deps, "-"))
		return 0;
	while (*deps && (NULL != ((comma = strstr(deps, ","))))) {
		*comma = '\0';

		m = find_module(deps);

		if (!m || (m->state != LOADED))
			return -1;

		deps = ++comma;
	}

	return 0;
}

static int load_depmod(void)
{
	int loaded, todo;
	struct module *m;

	do {
		loaded = 0;
		todo = 0;
		avl_for_each_element(&modules, m, avl) {
			if ((m->state == PROBE) && (!deps_available(m))) {
				if (!insert_module(get_module_path(m->name), "")) {
					m->state = LOADED;
					loaded++;
					continue;
				}
				m->state = FAILED;
			} else if (m->state == PROBE) {
				todo++;
			}
		}
//		printf("loaded %d modules this pass\n", loaded);
	} while (loaded);

//	printf("missing todos %d\n", todo);

	return -todo;
}

static int print_insmod_usage(void)
{
	fprintf(stderr, "Usage:\n\tinsmod filename [args]\n");

	return -1;
}

static int print_usage(char *arg)
{
	fprintf(stderr, "Usage:\n\t%s module\n", arg);

	return -1;
}

static int main_insmod(int argc, char **argv)
{
	char *name, *cur, *options;
	int i, ret, len;

	if (argc < 2)
		return print_insmod_usage();

	name = get_module_name(argv[1]);
	if (!name) {
		fprintf(stderr, "cannot find module - %s\n", argv[1]);
		return -1;
	}

	if (scan_loaded_modules())
		return -1;

	if (find_module(name)) {
		fprintf(stderr, "module is already loaded - %s\n", name);
		return -1;

	}

	free_modules();

	for (len = 0, i = 2; i < argc; i++)
		len += strlen(argv[i]) + 1;

	options = malloc(len);
	options[0] = 0;
	cur = options;
	for (i = 2; i < argc; i++) {
		if (options[0]) {
			*cur = ' ';
			cur++;
		}
		cur += sprintf(cur, "%s", argv[i]);
	}

	ret = insert_module(get_module_path(name), options);
	free(options);

	return ret;
}

static int main_rmmod(int argc, char **argv)
{
	struct module *m;
	char *name;
	int ret;

	if (argc != 2)
		return print_usage("rmmod");

	if (scan_loaded_modules())
		return -1;

	name = get_module_name(argv[1]);
	m = find_module(name);
	if (!m) {
		fprintf(stderr, "module is not loaded\n");
		return -1;
	}
	free_modules();

	ret = syscall(__NR_delete_module, name, 0);

	if (ret)
		fprintf(stderr, "unloading the module failed\n");

	return ret;
}

static int main_lsmod(int argc, char **argv)
{
	struct module *m;

	if (scan_loaded_modules())
		return -1;

	avl_for_each_element(&modules, m, avl)
		if (m->state == LOADED)
			printf("%-20s%8d%3d %s\n",
				m->name, m->size, m->usage,
				(*m->depends == '-') ? ("") : (m->depends));

	free_modules();

	return 0;
}

static int main_modinfo(int argc, char **argv)
{
	char *module;

	if (argc != 2)
		return print_usage("modinfo");

	module = get_module_path(argv[1]);
	if (!module) {
		fprintf(stderr, "cannot find module - %s\n", argv[1]);
		return -1;
	}

	print_modinfo(module);

	return 0;
}

static int main_depmod(int argc, char **argv)
{
	struct utsname ver;
	struct module *m;
	char *path;
	char *name;

	if (argc != 2)
		return print_usage("depmod");

	if (scan_loaded_modules())
		return -1;

	uname(&ver);
	path = alloca(sizeof(DEF_MOD_PATH "*.ko") + strlen(ver.release) + 1);
	sprintf(path, DEF_MOD_PATH "*.ko", ver.release);

	scan_module_folder(path);

	name = get_module_name(argv[1]);
	m = find_module(name);
	if (m && m->state == LOADED) {
		fprintf(stderr, "%s is already loaded\n", name);
		return -1;
	} else if (!m) {
		fprintf(stderr, "failed to find a module named %s\n", name);
	} else {
		m->state = PROBE;
		load_depmod();
	}

	free_modules();

	return 0;
}

static int main_loader(int argc, char **argv)
{
	int gl_flags = GLOB_NOESCAPE | GLOB_MARK;
	char *dir = "/etc/modules.d/*";
	glob_t gl;
	char *path;
	int j;

	if (argc > 1)
		dir = argv[1];

	if (argc > 2)
		prefix = argv[2];

	path = malloc(strlen(dir) + 2);
	strcpy(path, dir);
	strcat(path, "*");

	scan_loaded_modules();

	syslog(0, "kmodloader: loading kernel modules from %s\n", path);

	if (glob(path, gl_flags, NULL, &gl) < 0)
		goto out;

	for (j = 0; j < gl.gl_pathc; j++) {
		FILE *fp = fopen(gl.gl_pathv[j], "r");
		size_t mod_len = 0;
		char *mod = NULL;

		if (!fp) {
			fprintf(stderr, "failed to open %s\n", gl.gl_pathv[j]);
			continue;
		}

		while (getline(&mod, &mod_len, fp) > 0) {
			char *nl = strchr(mod, '\n');
			struct module *m;
			char *opts;

			if (nl)
				*nl = '\0';

			opts = strchr(mod, ' ');
			if (opts)
				*opts++ = '\0';

			m = find_module(get_module_name(mod));
			if (m)
				continue;
			insert_module(get_module_path(mod), (opts) ? (opts) : (""));
		}
		free(mod);
		fclose(fp);
	}

out:
	globfree(&gl);
	free(path);

	return 0;
}

int main(int argc, char **argv)
{
	char *exec = basename(*argv);

	avl_init(&modules, avl_strcmp, false, NULL);
	if (!strcmp(exec, "insmod"))
		return main_insmod(argc, argv);

	if (!strcmp(exec, "rmmod"))
		return main_rmmod(argc, argv);

	if (!strcmp(exec, "lsmod"))
		return main_lsmod(argc, argv);

	if (!strcmp(exec, "modinfo"))
		return main_modinfo(argc, argv);

	if (!strcmp(exec, "depmod"))
		return main_depmod(argc, argv);

	return main_loader(argc, argv);
}
