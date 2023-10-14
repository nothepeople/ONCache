#include "bpf/bpf.h"
#include "common_defines.h"

#ifndef __COMMON_USER_H
#define __COMMON_USER_H

bool locate_kern_object(char *execname, char *filename, size_t size);

#define BPF_DIR_MNT "/sys/fs/bpf"
int bpf_fs_check_and_fix();

int tc_new_qdisc(const char* dev);
int tc_attach_bpf(const char* dev, const char* bpf_obj,
    const char* sec_name, bool egress);
int tc_list_filter(const char* dev, bool egress);
int tc_remove_filter(const char* dev, bool egress);

#ifdef __cplusplus
extern "C" {
#endif
int open_bpf_map_file(const char *pin_dir,
        const char *mapname,
        struct bpf_map_info *info);

static int parse_u8(char *str, unsigned char *x)
{
    unsigned long z;

    z = strtoul(str, 0, 16);
    if (z > 0xff)
        return -1;

    if (x)
        *x = z;

    return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
    if (parse_u8(str, &mac[0]) < 0)
        return -1;
    if (parse_u8(str + 3, &mac[1]) < 0)
        return -1;
    if (parse_u8(str + 6, &mac[2]) < 0)
        return -1;
    if (parse_u8(str + 9, &mac[3]) < 0)
        return -1;
    if (parse_u8(str + 12, &mac[4]) < 0)
        return -1;
    if (parse_u8(str + 15, &mac[5]) < 0)
        return -1;

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif
