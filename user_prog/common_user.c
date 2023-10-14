// This file reuses some tool functions that are used
// to manage the TC programs from this repo:
// https://github.com/xdp-project/xdp-cpumap-tc.git

#include <libgen.h>
#include "common_user.h"
#include "common_defines.h"
#include "bpf/bpf_util.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

bool locate_kern_object(char *execname, char *filename, size_t size)
{
    char *basec, *bname;

    snprintf(filename, size, "%s", execname);

    if (access(filename, F_OK) != -1)
        return true;

    basec = strdup(execname);
    if (basec == NULL)
        return false;
    bname = basename(basec);

    /* Maybe enough to add a "./" */
    snprintf(filename, size, "./%s", bname);
    if (access(filename, F_OK) != -1) {
        free(basec);
        return true;
    }

    /* Maybe /usr/local/lib/ */
    snprintf(filename, size, "/usr/local/lib/%s", bname);
    if (access(filename, F_OK) != -1) {
        free(basec);
        return true;
    }

    /* Maybe /usr/local/bin/ */
    snprintf(filename, size, "/usr/local/bin/%s", bname);
    if (access(filename, F_OK) != -1) {
        free(basec);
        return true;
    }

    free(basec);
    return false;
}

#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC   0xcafe4a11
#endif

#define FILEMODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

/* Verify BPF-filesystem is mounted on given file path */
int __bpf_fs_check_path(const char *path)
{
    struct statfs st_fs;
    char *dname, *dir;
    int err = 0;

    if (path == NULL)
        return -EINVAL;

    dname = strdup(path);
    if (dname == NULL)
        return -ENOMEM;

    dir = dirname(dname);
    if (statfs(dir, &st_fs)) {
        fprintf(stderr, "ERR: failed to statfs %s: (%d)%s\n",
            dir, errno, strerror(errno));
        err = -errno;
    }
    free(dname);

    if (!err && st_fs.f_type != BPF_FS_MAGIC) {
        err = -EMEDIUMTYPE;
    }

    return err;
}

int __bpf_fs_subdir_check_and_fix(const char *dir)
{
    int err;

    err = access(dir, F_OK);
    if (err) {
        if (errno == EACCES) {
            fprintf(stderr, "ERR: "
                "Got root? dir access %s fail: %s\n",
                dir, strerror(errno));
            return -1;
        }
        err = mkdir(dir, FILEMODE);
        if (err) {
            fprintf(stderr, "ERR: mkdir %s failed: %s\n",
                dir, strerror(errno));
                return -1;
        }
        // printf("DEBUG: mkdir %s\n", dir);
    }

    return err;
}

int bpf_fs_check_and_fix()
{
    const char *some_base_path = BPF_DIR_MNT "/some_file";
    const char *dir_tc_globals = BPF_DIR_MNT "/tc/globals";
    const char *dir_tc = BPF_DIR_MNT "/tc";
    const char *target = BPF_DIR_MNT;
    bool did_mkdir = false;
    int err;

    err = __bpf_fs_check_path(some_base_path);

    if (err) {
        /* First fix step: mkdir /sys/fs/bpf if dir not exist */
        struct stat sb = {0};
        int ret;

        ret = stat(target, &sb);
        if (ret) {
            ret = mkdir(target, FILEMODE);
            if (ret) {
                fprintf(stderr, "mkdir %s failed: %s\n", target,
                    strerror(errno));
                return ret;
            }
            did_mkdir = true;
        }
    }

    if (err == -EMEDIUMTYPE || did_mkdir) {
        /* Fix step 2: Mount bpf filesystem */
        if (mount("bpf", target, "bpf", 0, "mode=0755")) {
            fprintf(stderr, "ERR: mount -t bpf bpf %s failed: %s\n",
                target, strerror(errno));
            return -1;
        }
    }

    /* Fix step 3: Check sub-directories exists */
    err = __bpf_fs_subdir_check_and_fix(dir_tc);
    if (err)
        return err;

    err = __bpf_fs_subdir_check_and_fix(dir_tc_globals);
    if (err)
        return err;

    return 0;
}

#define CMD_MAX  2048
#define CMD_MAX_TC 256
static char tc_cmd[CMD_MAX_TC] = "tc";

/*
 * TC require attaching the bpf-object via the TC cmdline tool.
 *
 * Manually like:
 *  $TC qdisc   del dev $DEV clsact
 *  $TC qdisc   add dev $DEV clsact
 *  $TC filter  add dev $DEV egress bpf da obj $BPF_OBJ sec $SEC_NAME
 *  $TC filter show dev $DEV egress
 *  $TC filter  del dev $DEV egress
 *
 * (The tc "replace" command does not seem to work as expected)
 */
int tc_new_qdisc(const char* dev)
{
    char cmd[CMD_MAX];
    int ret = 0;

    /* Step-1: Delete clsact, which also remove filters */
    memset(&cmd, 0, CMD_MAX);
    snprintf(cmd, CMD_MAX,
         "%s qdisc del dev %s clsact 2> /dev/null",
         tc_cmd, dev);
    if (verbose) printf(" - Run: %s\n", cmd);
    ret = system(cmd);
    if (!WIFEXITED(ret)) {
        fprintf(stderr,
            "ERR(%d): Cannot exec tc cmd\n Cmdline:%s\n",
            WEXITSTATUS(ret), cmd);
        exit(EXIT_FAILURE);
    } else if (WEXITSTATUS(ret) == 2) {
        /* Unfortunately TC use same return code for many errors */
        if (verbose) printf(" - (First time loading clsact?)\n");
    }

    /* Step-2: Attach a new clsact qdisc */
    memset(&cmd, 0, CMD_MAX);
    snprintf(cmd, CMD_MAX,
         "%s qdisc add dev %s clsact",
         tc_cmd, dev);
    if (verbose) printf(" - Run: %s\n", cmd);
    ret = system(cmd);
    if (ret) {
        fprintf(stderr,
            "ERR(%d): tc cannot attach qdisc hook\n Cmdline:%s\n",
            WEXITSTATUS(ret), cmd);
        exit(EXIT_FAILURE);
    }

    return ret;
}

int tc_attach_bpf(const char* dev, const char* bpf_obj,
             const char* sec_name, bool egress)
{
    char cmd[CMD_MAX];
    int ret = 0;

    /* Step-3: Attach BPF program/object as ingress filter */
    memset(&cmd, 0, CMD_MAX);
    if (egress) {
        snprintf(cmd, CMD_MAX,
             "%s filter add dev %s egress bpf da obj %s sec %s",
             tc_cmd, dev, bpf_obj, sec_name);
    } else {
        snprintf(cmd, CMD_MAX,
             "%s filter add dev %s ingress bpf da obj %s sec %s",
             tc_cmd, dev, bpf_obj, sec_name);
    }
    if (verbose) printf(" - Run: %s\n", cmd);
    ret = system(cmd);
    if (ret) {
        fprintf(stderr,
            "ERR(%d): tc cannot attach filter\n Cmdline:%s\n",
            WEXITSTATUS(ret), cmd);
        exit(EXIT_FAILURE);
    }

    return ret;
}

int tc_list_filter(const char* dev, bool egress)
{
    char cmd[CMD_MAX];
    int ret = 0;

    memset(&cmd, 0, CMD_MAX);
    if (egress) {
        snprintf(cmd, CMD_MAX,
             "%s filter show dev %s egress",
             tc_cmd, dev);
    } else {
        snprintf(cmd, CMD_MAX,
             "%s filter show dev %s ingress",
             tc_cmd, dev);
    }
    if (verbose) printf(" - Run: %s\n", cmd);
    ret = system(cmd);
    if (ret) {
        fprintf(stderr,
            "ERR(%d): tc cannot list filters\n Cmdline:%s\n",
            ret, cmd);
        exit(EXIT_FAILURE);
    }
    return ret;
}

int tc_remove_filter(const char* dev, bool egress)
{
    char cmd[CMD_MAX];
    int ret = 0;

    memset(&cmd, 0, CMD_MAX);
    if (egress) {
        snprintf(cmd, CMD_MAX,
             "%s filter del dev %s egress",
             tc_cmd, dev);
    } else {
        snprintf(cmd, CMD_MAX,
             "%s filter del dev %s ingress",
             tc_cmd, dev);
    }
    if (verbose) printf(" - Run: %s\n", cmd);
    ret = system(cmd);
    if (ret) {
        fprintf(stderr,
            "ERR(%d): tc cannot remove filters\n Cmdline:%s\n",
            ret, cmd);
        exit(EXIT_FAILURE);
    }
    return ret;
}

int open_bpf_map_file(const char *pin_dir,
              const char *mapname,
              struct bpf_map_info *info)
{
    char filename[PATH_MAX];
    int err, len, fd;
    __u32 info_len = sizeof(*info);

    len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
    if (len < 0) {
        fprintf(stderr, "ERR: constructing full mapname path\n");
        return -1;
    }

    fd = bpf_obj_get(filename);
    if (fd < 0) {
        fprintf(stderr,
            "WARN: Failed to open bpf map file:%s err(%d):%s\n",
            filename, errno, strerror(errno));
        return fd;
    }

    if (info) {
        err = bpf_obj_get_info_by_fd(fd, info, &info_len);
        if (err) {
            fprintf(stderr, "ERR: %s() can't get info - %s\n",
                __func__,  strerror(errno));
            return EXIT_FAIL_BPF;
        }
    }

    return fd;
}
