#include "common_user.h"
#include <yaml-cpp/yaml.h>

int update_map_element(const char* pin_dir, const char * map_name, const void* key, const void* value) {
    int map_fd = open_bpf_map_file(pin_dir, map_name, NULL);
    if (map_fd < 0) {
        return EXIT_FAIL_BPF;
    }
    int err = bpf_map_update_elem(map_fd, key, value, 0);
    if (err < 0) {
        fprintf(stderr, "ERR: bpf_map_update_elem\n");
        return EXIT_FAIL_BPF;
    }
    return 0;
}

int fillup_init_map(const char* pin_dir, const char* file_name) {
    int err, key;
    YAML::Node data_node = YAML::LoadFile(file_name)["ingress_cache"];
    for (auto it = data_node.begin(); it != data_node.end(); it++) {
        __be32 pod_ip = inet_addr((char*)it->first.as<std::string>().data());

        struct ingressinfo ingressinfo_;
        ingressinfo_.ifidx = it->second["ifidx"].as<int>();
        char default_mac[18] = "00:00:00:00:00:00";
        if (parse_mac(default_mac, ingressinfo_.dmac) < 0) {
            return EXIT_FAIL_OPTION;
        }
        if (parse_mac(default_mac, ingressinfo_.smac) < 0) {
            return EXIT_FAIL_OPTION;
        }
        // Update data to ingress_cache map
        err = update_map_element(pin_dir, "ingress_cache", &pod_ip, &ingressinfo_);
        if (err) {
            printf("ERR: ingress_cache\n");
        }
    }

    data_node = YAML::LoadFile(file_name)["devmap"];
    for (auto it = data_node.begin(); it != data_node.end(); it++) {
        key = it->first.as<int>();
        char ip_str[16];
        it->second["ip"].as<std::string>().copy(ip_str, 16, 0);
        __be32 ip = inet_addr(ip_str);
        struct devinfo devinfo_ = {
            .ip = ip
        };
        char mac_str[18];
        it->second["mac"].as<std::string>().copy(mac_str, 18, 0);
        if (parse_mac(mac_str, devinfo_.mac) < 0) {
            return EXIT_FAIL_OPTION;
        }
        // Update data to devmap map
        err = update_map_element(pin_dir, "devmap", &key, &devinfo_);
        if (err) {
            printf("ERR: devmap\n");
        }
    }
    return EXIT_SUCCESS;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf/";

int main(int argc, char **argv)
{
    int err, len;
    char pin_dir[PATH_MAX];

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, "tc/globals/");
    err = fillup_init_map(pin_dir, "mapdata.yaml");

    if(err < 0) return EXIT_FAIL_BPF;
    return EXIT_OK;
}