#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <lkl.h>
#include <lkl_host.h>
#ifndef __MINGW32__
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#else
#include <windows.h>
#endif

#include "test.h"
#include "cla.h"

static struct {
	int printk;
	const char *disk;
	const char *fstype;
	int partition;
} cla;

struct cl_arg args[] = {
	{"disk", 'd', "disk file to use", 1, CL_ARG_STR, &cla.disk},
	{"partition", 'P', "partition to mount", 1, CL_ARG_INT, &cla.partition},
	{"type", 't', "filesystem type", 1, CL_ARG_STR, &cla.fstype},
	{0},
};


static char mnt_point[32];

static long lkl_mount_dev2(unsigned int dev, unsigned int part,
		   const char *fs_type, int flags,
		   const char *data, char *mnt_str, unsigned int mnt_str_len)
{
	char dev_str[] = { "/dev/xxxxxxxx" };
	int err;
	char _data[4096]; /* FIXME: PAGE_SIZE is not exported by LKL */

	if (mnt_str_len < sizeof(dev_str))
		return -LKL_ENOMEM;

	snprintf(dev_str, sizeof(dev_str), "/dev/%08x", dev);
	snprintf(mnt_str, mnt_str_len, "/mnt/%08x", dev);

	err = lkl_sys_access("/dev", LKL_S_IRWXO);
	if (err < 0) {
		if (err == -LKL_ENOENT)
			err = lkl_sys_mkdir("/dev", 0700);
		if (err < 0)
			return err;
	}

	err = lkl_sys_mknod(dev_str, LKL_S_IFBLK | 0600, dev);
	if (err < 0)
		return err;

	err = lkl_sys_access("/mnt", LKL_S_IRWXO);
	if (err < 0) {
		if (err == -LKL_ENOENT)
			err = lkl_sys_mkdir("/mnt", 0700);
		if (err < 0)
			return err;
	}

	err = lkl_sys_mkdir(mnt_str, 0700);
	if (err < 0) {
		lkl_sys_unlink(dev_str);
		return err;
	}

	/* kernel always copies a full page */
	if (data) {
		strncpy(_data, data, sizeof(_data));
		_data[sizeof(_data) - 1] = 0;
	} else {
		_data[0] = 0;
	}

	err = lkl_sys_mount(dev_str, mnt_str, (char *)fs_type, flags, _data);
	if (err < 0) {
		lkl_sys_unlink(dev_str);
		lkl_sys_rmdir(mnt_str);
		return err;
	}

	return 0;
}

LKL_TEST_CALL(mount_dev, lkl_mount_dev2, 0, LKL_MKDEV(259, 0), cla.partition, cla.fstype, 
 	      0, NULL, mnt_point, sizeof(mnt_point)) 

  long lkl_umount_dev2(unsigned int dev, unsigned int part, int flags,
		    long timeout_ms)
{
	char dev_str[] = { "/dev/xxxxxxxx" };
	char mnt_str[] = { "/mnt/xxxxxxxx" };
	int err;

	snprintf(dev_str, sizeof(dev_str), "/dev/%08x", dev);
	snprintf(mnt_str, sizeof(mnt_str), "/mnt/%08x", dev);

	err = lkl_umount_timeout(mnt_str, flags, timeout_ms);
	if (err)
		return err;

	err = lkl_sys_unlink(dev_str);
	if (err)
		return err;

	return lkl_sys_rmdir(mnt_str);
}

static int lkl_test_umount_dev(void)
{
	long ret, ret2;

	ret = lkl_sys_chdir("/");

	ret2 = lkl_umount_dev2(LKL_MKDEV(259, 0), cla.partition, 0, 1000);

	lkl_test_logf("%ld %ld", ret, ret2);

	if (!ret && !ret2)
		return TEST_SUCCESS;

	return TEST_FAILURE;
}

struct lkl_dir *dir;

static int lkl_test_opendir(void)
{
	int err;

	dir = lkl_opendir(mnt_point, &err);

	lkl_test_logf("lkl_opedir(%s) = %d %s\n", mnt_point, err,
		      lkl_strerror(err));

	if (err == 0)
		return TEST_SUCCESS;

	return TEST_FAILURE;
}

static int lkl_test_readdir(void)
{
	struct lkl_linux_dirent64 *de = lkl_readdir(dir);
	int wr = 0;

	while (de) {
		wr += lkl_test_logf("%s ", de->d_name);
		if (wr >= 70) {
			lkl_test_logf("\n");
			wr = 0;
			break;
		}
		de = lkl_readdir(dir);
	}

	if (lkl_errdir(dir) == 0)
		return TEST_SUCCESS;

	return TEST_FAILURE;
}

LKL_TEST_CALL(closedir, lkl_closedir, 0, dir);
LKL_TEST_CALL(chdir_mnt_point, lkl_sys_chdir, 0, mnt_point);
LKL_TEST_CALL(start_kernel, lkl_start_kernel, 0, &lkl_host_ops,
	     "mem=16M loglevel=8");
LKL_TEST_CALL(stop_kernel, lkl_sys_halt, 0);

struct lkl_test tests[] = {
	LKL_TEST(start_kernel),
	LKL_TEST(mount_dev),
	LKL_TEST(chdir_mnt_point),
	LKL_TEST(opendir),
	LKL_TEST(readdir),
	LKL_TEST(closedir),
	LKL_TEST(umount_dev),
	LKL_TEST(stop_kernel),
};

int main(int argc, const char **argv)
{
	if (parse_args(argc, argv, args) < 0)
		return -1;

	lkl_host_ops.print = lkl_test_log;

	return lkl_test_run(tests, sizeof(tests)/sizeof(struct lkl_test),
			    "disk %s", cla.fstype);
}
