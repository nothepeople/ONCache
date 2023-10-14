// This file reuses some tool functions that are used
// to parse the user commands from this repo:
// https://github.com/xdp-project/xdp-cpumap-tc.git

#include "common_user.h"
#include "bpf/bpf_util.h"
static const struct option long_options[] = {
    {"help", no_argument,  NULL, 'h' },
    {"list", no_argument,  NULL, 'l' },
    {"quiet", no_argument,  NULL, 'q' },
    {"remove", no_argument, NULL, 'r'},
    {"dev" , required_argument, NULL, 'd' },
    {"filename", required_argument, NULL, 'f'},
    {"sec-name", required_argument, NULL, 's'},
    {"egress", no_argument, NULL, 'e'},
    {"new-qdisc", no_argument, NULL, 'n'},
    {0, 0, NULL,  0 }
};

static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static int ifindex = -1;

int main(int argc, char **argv)
{
    int opt, longindex = 0;
    bool do_list = false, do_remove = false;
    char filename[512];
    char kern_file_name[512];
    char sec_name[512];
    bool egress = false;

    /* Depend on sharing pinned maps */
    if (bpf_fs_check_and_fix()) {
        fprintf(stderr, "ERR: "
            "Need access to bpf-fs(%s) for pinned maps "
            "(%d): %s\n", BPF_DIR_MNT, errno, strerror(errno));
        return EXIT_FAIL_MAP_FS;
    }

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hqlrdfs",
                  long_options, &longindex)) != -1) {
        switch (opt) {
        case 'q':
            verbose = 0;
            break;
        case 'l':
            do_list = true;
            break;
        case 'r':
            do_remove = true;
            break;
        case 'd':
            if (strlen(optarg) >= IF_NAMESIZE) {
                fprintf(stderr, "ERR: --dev name too long\n");
                goto error;
            }
            ifname = (char *)&ifname_buf;
            strncpy(ifname, optarg, IF_NAMESIZE);
            ifindex = if_nametoindex(ifname);
            if (ifindex == 0) {
                fprintf(stderr,
                    "ERR: --dev name unknown err(%d):%s\n",
                    errno, strerror(errno));
                goto error;
            }
            if (ifindex >= MAX_IFINDEX) {
                fprintf(stderr,
                    "ERR: Fix MAX_IFINDEX err(%d):%s\n",
                    errno, strerror(errno));
                goto error;
            }
            break;
        case 'f':
            if (strlen(optarg) >= 512) {
                fprintf(stderr, "ERR: --file name too long\n");
                goto error;
            }
            strncpy(kern_file_name, optarg, 512);
            break;
        case 's':
            if (strlen(optarg) >= 512) {
                fprintf(stderr, "ERR: --sec name too long\n");
                goto error;
            }
            strncpy(sec_name, optarg, 512);
            break;
        case 'e':
            egress = true;
            break;
        case 'n':
            if (tc_new_qdisc(ifname)) {
                fprintf(stderr, "ERR: tc_new_qdisc err\n");
                goto error;
            }
            break;
        case 'h':
        error:
        default:
            return EXIT_FAIL_OPTION;
        }
    }

    if (do_remove) {
        tc_remove_filter(ifname, egress);
        return EXIT_OK;
    }

    if (!locate_kern_object(kern_file_name, filename, sizeof(filename))) {
        fprintf(stderr, "ERR: "
            "cannot locate BPF _kern.o ELF file:%s errno(%d):%s\n",
            filename, errno, strerror(errno));
        return EXIT_FAIL_BPF_ELF;
    }

    if (ifindex > 0 && !do_list) {
        int err;

        if (verbose)
            printf("Dev:%s -- Loading: TC-clsact egress\n", ifname);

        err = tc_attach_bpf(ifname, filename, sec_name, egress);
        if (err) {
            fprintf(stderr, "ERR: dev:%s"
                " Fail TC-clsact loading %s sec:%s\n",
                ifname, filename, sec_name);
            return err;
        }
    }

    if (do_list) {
        if (ifindex > 0)
            tc_list_filter(ifname, egress);
    }

    return EXIT_OK;
}
