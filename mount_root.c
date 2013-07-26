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

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <glob.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <asm/byteorder.h>

#include <mtd/mtd-user.h>

#define DEBUG(level, fmt, ...) do { \
	if (debug >= level) \
		fprintf(stderr, "%s %s(%d): " fmt, argv0, __func__, __LINE__, ## __VA_ARGS__); \
	} while (0)

#define LOG(fmt, ...) do { \
		syslog(LOG_INFO, fmt, ## __VA_ARGS__); \
		fprintf(stderr, "%s: "fmt, argv0, ## __VA_ARGS__); \
	} while (0)

#define ERROR(fmt, ...) do { \
		syslog(LOG_ERR, fmt, ## __VA_ARGS__); \
		fprintf(stderr, "%s: "fmt, argv0, ## __VA_ARGS__); \
	} while (0)

enum {
	FS_NONE,
	FS_JFFS2,
	FS_DEADCODE,
};

static const char *argv0;

/* this is a raw syscall - man 2 pivot_root */
extern int pivot_root(const char *new_root, const char *put_old);

static int debug = 0;

static void foreachdir(const char *dir, int (*cb)(const char*))
{
	char globdir[256];
	glob_t gl;
	int j;

	if (dir[strlen(dir) - 1] == '/')
		snprintf(globdir, 256, "%s*", dir);
	else
		snprintf(globdir, 256, "%s/*", dir);

	if (!glob(globdir, GLOB_NOESCAPE | GLOB_MARK | GLOB_ONLYDIR, NULL, &gl))
		for (j = 0; j < gl.gl_pathc; j++)
			foreachdir(gl.gl_pathv[j], cb);

	cb(dir);
}

static int find_overlay_mount(char *overlay)
{
	FILE *fp = fopen("/proc/mounts", "r");
	static char line[256];
	int ret = -1;

	if(!fp)
		return ret;

	while (ret && fgets(line, sizeof(line), fp))
		if (!strncmp(line, overlay, strlen(overlay)))
			ret = 0;

	fclose(fp);

	return ret;
}

static char* find_mount(char *mp)
{
	FILE *fp = fopen("/proc/mounts", "r");
	static char line[256];
	char *point = NULL;

	if(!fp)
		return NULL;

	while (fgets(line, sizeof(line), fp)) {
		char *s, *t = strstr(line, " ");

		if (!t)
			return NULL;
		t++;
		s = strstr(t, " ");
		if (!s)
			return NULL;
		*s = '\0';

		if (!strcmp(t, mp)) {
			fclose(fp);
			return t;
		}
	}

	fclose(fp);

	return point;
}

static char* find_mount_point(char *block, char *fs)
{
	FILE *fp = fopen("/proc/mounts", "r");
	static char line[256];
	int len = strlen(block);
	char *point = NULL;

	if(!fp)
		return NULL;

	while (fgets(line, sizeof(line), fp)) {
		if (!strncmp(line, block, len)) {
			char *p = &line[len + 1];
			char *t = strstr(p, " ");

			if (!t)
				return NULL;

			*t = '\0';
			t++;

			if (fs && strncmp(t, fs, strlen(fs))) {
				ERROR("block is mounted with wrong fs\n");
				return NULL;
			}
			point = p;
			break;
		}
	}

	fclose(fp);

	return point;
}

static char* find_mtd_index(char *name)
{
	FILE *fp = fopen("/proc/mtd", "r");
	static char line[256];
	char *index = NULL;

	if(!fp)
		return index;

	while (!index && fgets(line, sizeof(line), fp)) {
		if (strstr(line, name)) {
			char *eol = strstr(line, ":");

			if (!eol)
				continue;

			*eol = '\0';
			index = &line[3];
			DEBUG(1, "found %s -> index:%s\n", name, index);
		}
	}

	fclose(fp);

	return index;
}

static int find_mtd_block(char *name, char *part, int plen)
{
	char *index = find_mtd_index(name);

	if (!index)
		return -1;

	snprintf(part, plen, "/dev/mtdblock%s", index);
	DEBUG(1, "found %s -> %s\n", name, part);

	return 0;
}

static int find_mtd_char(char *name, char *part, int plen)
{
	char *index = find_mtd_index(name);

	if (!index)
		return -1;

	snprintf(part, plen, "/dev/mtd%s", index);
	DEBUG(1, "found %s -> %s\n", name, part);

	return 0;
}

static int mtd_unlock(char *mtd)
{
	struct erase_info_user mtdlock;
	struct mtd_info_user mtdinfo;
	int fd = open(mtd, O_RDWR | O_SYNC);
	int ret = -1;

	DEBUG(1, "%s\n", mtd);

	if (!fd) {
		ERROR("failed to open %s: %s\n", mtd, strerror(errno));
		return -1;
	}

	ret = ioctl(fd, MEMGETINFO, &mtdinfo);
	if (ret) {
		ERROR("ioctl(%s, MEMGETINFO) failed: %s\n", mtd, strerror(errno));
		goto err_out;
	}

	mtdlock.start = 0;
	mtdlock.length = mtdinfo.size;
	ioctl(fd, MEMUNLOCK, &mtdlock);

err_out:
	close(fd);

	return ret;
}

static int mtd_mount_jffs2(void)
{
	char rootfs_data[32];

	if (mkdir("/tmp/overlay", 0755)) {
		ERROR("failed to mkdir /tmp/overlay: %s\n", strerror(errno));
		return -1;
	}

	if (find_mtd_block("rootfs_data", rootfs_data, sizeof(rootfs_data))) {
		ERROR("rootfs_data does not exist\n");
		return -1;
	}

	if (mount(rootfs_data, "/tmp/overlay", "jffs2", MS_NOATIME, NULL)) {
		ERROR("failed to mount -t jffs2 %s /tmp/overlay: %s\n", rootfs_data, strerror(errno));
		return -1;
	}

	find_mtd_char("rootfs_data", rootfs_data, sizeof(rootfs_data));

	return mtd_unlock(rootfs_data);
}

static int jffs2_ready(char *mtd)
{
	FILE *fp = fopen(mtd, "r");
	__u32 deadc0de;
	__u16 jffs2;
	size_t sz;

	if (!fp) {
		ERROR("reading %s failed\n", mtd);
		exit(-1);
	}

	sz = fread(&deadc0de, sizeof(deadc0de), 1, fp);
	fclose(fp);

	if (sz != 1) {
		ERROR("reading %s failed: %s\n", mtd, strerror(errno));
		exit(-1);
	}

	deadc0de = __be32_to_cpu(deadc0de);
	jffs2 = __be16_to_cpu(deadc0de >> 16);

	if (jffs2 == 0x1985) {
		LOG("jffs2 is ready\n");
		return FS_JFFS2;
	}

	if (deadc0de == 0xdeadc0de) {
		LOG("jffs2 is not ready - marker found\n");
		return FS_DEADCODE;
	}

	ERROR("No jffs2 marker was found\n");

	return FS_NONE;
}

static int check_fs_exists(char *fs)
{
	FILE *fp = fopen("/proc/filesystems", "r");
	static char line[256];
	int ret = -1;

	DEBUG(2, "%s\n", fs);

	if (!fp) {
		ERROR("opening /proc/filesystems failed: %s\n", strerror(errno));
		goto out;
	}

	while (ret && fgets(line, sizeof(line), fp))
		if (strstr(line, fs))
			ret = 0;

	fclose(fp);

out:
	return ret;
}

static int mount_move(char *oldroot, char *newroot, char *dir)
{
#ifndef MS_MOVE
#define MS_MOVE	(1 << 13)
#endif
	struct stat s;
	char olddir[64];
	char newdir[64];
	int ret;

	DEBUG(2, "%s %s %s\n", oldroot, newroot, dir);

	snprintf(olddir, sizeof(olddir), "%s%s", oldroot, dir);
	snprintf(newdir, sizeof(newdir), "%s%s", newroot, dir);

	if (stat(olddir, &s) || !S_ISDIR(s.st_mode))
		return -1;

	if (stat(newdir, &s) || !S_ISDIR(s.st_mode))
		return -1;

	ret = mount(olddir, newdir, NULL, MS_NOATIME | MS_MOVE, NULL);

	if (ret)
		DEBUG(1, "failed %s %s: %s\n", olddir, newdir, strerror(errno));

	return ret;
}

static int pivot(char *new, char *old)
{
	char pivotdir[64];
	int ret;

	DEBUG(2, "%s %s\n", new, old);

	if (mount_move("", new, "/proc"))
		return -1;

	snprintf(pivotdir, sizeof(pivotdir), "%s%s", new, old);

	ret = pivot_root(new, pivotdir);

	if (ret < 0) {
		ERROR("pivot_root failed %s %s: %s\n", new, pivotdir, strerror(errno));
		return -1;
	}

	mount_move(old, "", "/dev");
	mount_move(old, "", "/tmp");
	mount_move(old, "", "/sys");
	mount_move(old, "", "/overlay");

	return 0;
}

static int fopivot(char *rw_root, char *ro_root)
{
	char overlay[64], lowerdir[64];

	DEBUG(2, "%s %s\n", rw_root, ro_root);

	if (check_fs_exists("overlay")) {
		ERROR("BUG: no suitable fs found\n");
		return -1;
	}

	snprintf(overlay, sizeof(overlay), "overlayfs:%s", rw_root);
	snprintf(lowerdir, sizeof(lowerdir), "lowerdir=/,upperdir=%s", rw_root);

	if (mount(overlay, "/mnt", "overlayfs", MS_NOATIME, lowerdir)) {
		ERROR("mount failed: %s\n", strerror(errno));
		return -1;
	}

	return pivot("/mnt", ro_root);
}

static int ramoverlay(void)
{
	DEBUG(2, "\n");

	mkdir("/tmp/root", 0755);
	mount("tmpfs", "/tmp/root", "tmpfs", MS_NOATIME, "mode=0755");

	return fopivot("/tmp/root", "/rom");
}

static int switch2jffs(void)
{
	char mtd[32];

	if (find_mtd_block("rootfs_data", mtd, sizeof(mtd))) {
		ERROR("no rootfs_data was found\n");
		return -1;
	}

	if (mount(mtd, "/rom/overlay", "jffs2", MS_NOATIME, NULL)) {
		ERROR("failed - mount -t jffs2 %s /rom/overlay: %s\n", mtd, strerror(errno));
		return -1;
	}

	if (mount("none", "/", NULL, MS_NOATIME | MS_REMOUNT, 0)) {
		ERROR("failed - mount -o remount,ro none: %s\n", strerror(errno));
		return -1;
	}

	system("cp -a /tmp/root/* /rom/overlay");

	if (pivot("/rom", "/mnt")) {
		ERROR("failed - pivot /rom /mnt: %s\n", strerror(errno));
		return -1;
	}

	if (mount_move("/mnt", "/tmp/root", "")) {
		ERROR("failed - mount -o move /mnt /tmp/root %s\n", strerror(errno));
		return -1;
	}

	return fopivot("/overlay", "/rom");
}

static int handle_whiteout(const char *dir)
{
	struct stat s;
	char link[256];
	ssize_t sz;
	struct dirent **namelist;
	int n;

	n = scandir(dir, &namelist, NULL, NULL);

	if (n < 1)
		return -1;

	while (n--) {
		char file[256];

		snprintf(file, sizeof(file), "%s%s", dir, namelist[n]->d_name);
		if (!lstat(file, &s) && S_ISLNK(s.st_mode)) {
			sz = readlink(file, link, sizeof(link) - 1);
			if (sz > 0) {
				char *orig;

				link[sz] = '\0';
				orig = strstr(&file[1], "/");
				if (orig && !strcmp(link, "(overlay-whiteout)")) {
					DEBUG(1, "unlinking %s\n", orig);
					unlink(orig);
				}
			}
		}
		free(namelist[n]);
	}
	free(namelist);

	return 0;
}

static int mtd_erase(const char *mtd)
{
	int fd = open(mtd, O_RDWR | O_SYNC);
	struct mtd_info_user i;
	struct erase_info_user e;
	int ret;

	if (!fd) {
		ERROR("failed to open %s: %s\n", mtd, strerror(errno));
		return -1;
	}

	ret = ioctl(fd, MEMGETINFO, &i);
	if (ret) {
		ERROR("ioctl(%s, MEMGETINFO) failed: %s\n", mtd, strerror(errno));
		return -1;
	}

	e.length = i.erasesize;
	for (e.start = 0; e.start < i.size; e.start += i.erasesize) {
		ioctl(fd, MEMUNLOCK, &e);
		if(ioctl(fd, MEMERASE, &e))
			ERROR("Failed to erase block on %s at 0x%x\n", mtd, e.start);
	}

	close(fd);
	return 0;
}

static int ask_user(int argc, char **argv)
{
	if ((argc < 2) || strcmp(argv[1], "-y")) {
		LOG("This will erase all settings and remove any installed packages. Are you sure? [N/y]\n");
		if (getchar() != 'y')
			return -1;
	}
	return 0;

}

static int handle_rmdir(const char *dir)
{
	struct stat s;
	struct dirent **namelist;
	int n;

	n = scandir(dir, &namelist, NULL, NULL);

	if (n < 1)
		return -1;

	while (n--) {
		char file[256];

		snprintf(file, sizeof(file), "%s%s", dir, namelist[n]->d_name);
		if (!lstat(file, &s) && !S_ISDIR(s.st_mode)) {
			DEBUG(1, "unlinking %s\n", file);
			unlink(file);
		}
		free(namelist[n]);
	}
	free(namelist);

	DEBUG(1, "rmdir %s\n", dir);
	rmdir(dir);

	return 0;
}

static int main_jffs2reset(int argc, char **argv)
{
	char mtd[32];
	char *mp;

	if (ask_user(argc, argv))
		return -1;

	if (check_fs_exists("overlay")) {
		ERROR("overlayfs not found\n");
		return -1;
	}

	if (find_mtd_block("rootfs_data", mtd, sizeof(mtd))) {
		ERROR("no rootfs_data was found\n");
		return -1;
	}

	mp = find_mount_point(mtd, "jffs2");
	if (mp) {
		LOG("%s is mounted as %s, only ereasing files\n", mtd, mp);
		foreachdir(mp, handle_rmdir);
		mount(mp, "/", NULL, MS_REMOUNT, 0);
	} else {
		LOG("%s is not mounted, erasing it\n", mtd);
		find_mtd_char("rootfs_data", mtd, sizeof(mtd));
		mtd_erase(mtd);
	}

	return 0;
}

static int main_jffs2mark(int argc, char **argv)
{
	FILE *fp;
	__u32 deadc0de = __cpu_to_be32(0xdeadc0de);
	char mtd[32];
	size_t sz;

	if (ask_user(argc, argv))
		return -1;

	if (find_mtd_block("rootfs_data", mtd, sizeof(mtd))) {
		ERROR("no rootfs_data was found\n");
		return -1;
	}

	fp = fopen(mtd, "w");
	LOG("%s - marking with deadc0de\n", mtd);
	if (!fp) {
		ERROR("opening %s failed\n", mtd);
		return -1;
	}

	sz = fwrite(&deadc0de, sizeof(deadc0de), 1, fp);
	fclose(fp);

	if (sz != 1) {
		ERROR("writing %s failed: %s\n", mtd, strerror(errno));
		return -1;
	}

	return 0;
 }
static int main_switch2jffs(int argc, char **argv)
{
	char mtd[32];
	char *mp;
	int ret = -1;

	if (find_overlay_mount("overlayfs:/tmp/root"))
		return -1;

	if (check_fs_exists("overlay")) {
		ERROR("overlayfs not found\n");
		return ret;
	}

	find_mtd_block("rootfs_data", mtd, sizeof(mtd));
	mp = find_mount_point(mtd, NULL);
	if (mp) {
		LOG("rootfs_data:%s is already mounted as %s\n", mtd, mp);
		return -1;
	}

	if (find_mtd_char("rootfs_data", mtd, sizeof(mtd))) {
		ERROR("no rootfs_data was found\n");
		return ret;
	}

	switch (jffs2_ready(mtd)) {
	case FS_NONE:
		ERROR("no jffs2 marker found\n");
		/* fall through */

	case FS_DEADCODE:
		ret = switch2jffs();
		if (!ret) {
			DEBUG(1, "doing fo cleanup\n");
			umount2("/tmp/root", MNT_DETACH);
			foreachdir("/overlay/", handle_whiteout);
		}
		break;

	case FS_JFFS2:
		ret = mtd_mount_jffs2();
		if (ret)
			break;
		if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
			ERROR("switching to jffs2 failed\n");
			ret = -1;
		}
		break;
	}

	return ret;
}

static int extroot(const char *prefix)
{
	char block_path[32];
	char kmod_loader[64];
	struct stat s;
	pid_t pid;

	sprintf(block_path, "%s/sbin/block", prefix);

	if (stat(block_path, &s))
		return -1;

	sprintf(kmod_loader, "/sbin/kmodloader %s/etc/modules-boot.d/ %s", prefix, prefix);
	system(kmod_loader);

	pid = fork();
	if (!pid) {
		mkdir("/tmp/extroot", 0755);
		execl(block_path, block_path, "extroot", NULL);
		exit(-1);
	} else if (pid > 0) {
		int status;

		waitpid(pid, &status, 0);
		if (!WEXITSTATUS(status)) {
			if (find_mount("/tmp/extroot/mnt")) {
				mount("/dev/root", "/", NULL, MS_NOATIME | MS_REMOUNT | MS_RDONLY, 0);

				mkdir("/tmp/extroot/mnt/proc", 0755);
				mkdir("/tmp/extroot/mnt/dev", 0755);
				mkdir("/tmp/extroot/mnt/sys", 0755);
				mkdir("/tmp/extroot/mnt/tmp", 0755);
				mkdir("/tmp/extroot/mnt/rom", 0755);

				if (mount_move("/tmp/extroot", "", "/mnt")) {
					ERROR("moving pivotroot failed - continue normal boot\n");
					umount("/tmp/extroot/mnt");
				} else if (pivot("/mnt", "/rom")) {
					ERROR("switching to pivotroot failed - continue normal boot\n");
					umount("/mnt");
				} else {
					umount("/tmp/overlay");
					rmdir("/tmp/overlay");
					rmdir("/tmp/extroot/mnt");
					rmdir("/tmp/extroot");
					return 0;
				}
			} else if (find_mount("/tmp/extroot/overlay")) {
				if (mount_move("/tmp/extroot", "", "/overlay")) {
					ERROR("moving extroot failed - continue normal boot\n");
					umount("/tmp/extroot/overlay");
				} else if (fopivot("/overlay", "/rom")) {
					ERROR("switching to extroot failed - continue normal boot\n");
					umount("/overlay");
				} else {
					umount("/tmp/overlay");
					rmdir("/tmp/overlay");
					rmdir("/tmp/extroot/overlay");
					rmdir("/tmp/extroot");
					return 0;
				}
			}
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	char *mp;
	char mtd[32];

	argv0 = basename(*argv);

	if (!strcmp(basename(*argv), "jffs2mark"))
		return main_jffs2mark(argc, argv);

	if (!strcmp(basename(*argv), "jffs2reset"))
		return main_jffs2reset(argc, argv);

	if (!strcmp(basename(*argv), "switch2jffs"))
		return main_switch2jffs(argc, argv);

	if (!getenv("PREINIT"))
		return -1;

	if (find_mtd_char("rootfs_data", mtd, sizeof(mtd))) {
		if (!find_mtd_char("rootfs", mtd, sizeof(mtd)))
			mtd_unlock(mtd);
		LOG("mounting /dev/root\n");
		mount("/dev/root", "/", NULL, MS_NOATIME | MS_REMOUNT, 0);
	} else {
		if (!extroot("")) {
			fprintf(stderr, "mount_root: switched to extroot\n");
			return 0;
		}

		switch (jffs2_ready(mtd)) {
		case FS_NONE:
		case FS_DEADCODE:
			return ramoverlay();

		case FS_JFFS2:
			find_mtd_block("rootfs_data", mtd, sizeof(mtd));
			mp = find_mount_point(mtd, NULL);
			if (mp) {
				LOG("rootfs_data:%s is already mounted as %s\n", mtd, mp);
				return -1;
			}

			mtd_mount_jffs2();

			if (!extroot("/tmp/overlay")) {
				fprintf(stderr, "mount_root: switched to extroot\n");
				return 0;
			}

			DEBUG(1, "switching to jffs2\n");
			if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
				ERROR("switching to jffs2 failed - fallback to ramoverlay\n");
				return ramoverlay();
			}
		}
	}

	return 0;
}
