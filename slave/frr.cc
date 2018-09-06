/*
 * UseExternalMap shows how to access an external map through
 * C++ interface. The external map could be a pinned map.
 * This example simulates the pinned map through a locally
 * created map by calling libbpf bpf_create_map.
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <stdint.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <arpa/inet.h>
#include <fmt/core.h>

#include "BPF.h"

#define NB_MAX_SEGS 5
#define NB_TIMERS 100

struct bfd_entry {
	uint64_t timestamp;
	uint16_t seq;
	uint16_t ack;
};

#define CHECK(condition, msg)        \
  ({                                 \
    if (condition) {                 \
      std::cerr << msg << std::endl; \
      exit(1);                       \
    }                                \
  })

const std::string BPF_PROGRAM_TPL = R"(
#define NB_MAX_SEGS 10
#define NB_TIMERS 100

struct bfd_entry {{
	uint64_t timestamp;
	uint16_t seq;
	uint16_t ack;
}};

BPF_TABLE("extern", u32, struct bfd_entry, sr6_bfd_timers, NB_TIMERS);

int frr(struct __sk_buff *skb) {{
    uint32_t key = {entry_id};
    struct bfd_entry *entry = sr6_bfd_timers.lookup(&key);
    if (!entry)
        return BPF_DROP;

    if (entry->timestamp != 0 && bpf_ktime_get_ns() <= entry->timestamp + {threshold})
        return BPF_OK;

    char srh[] = {{ 0, {hdrlen}, 4, {nseg},
                    {nseg}, 0, 0, 0,
                    {segments}
                 }};

    int ret = bpf_lwt_push_encap(skb, 0, (void *)srh, sizeof(srh));
    if (ret != 0) {{
            bpf_trace_printk("SRv6 FRR: incorrect SRH\\n");
            return BPF_DROP;
    }}

    return BPF_OK;
}}
)";

std::vector<std::string> split_segments(char *str)
{
    std::vector<std::string> v;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, ',')) {
        v.push_back(token);
    }

    return v;
}

std::string build_prog(char *argv[], uint64_t threshold_ns)
{
    std::vector<std::string> frr_segs = split_segments(argv[4]);
    size_t buf_len = sizeof(struct in6_addr) * frr_segs.size();
    unsigned char *buf = (unsigned char *)malloc(buf_len);
    CHECK(buf == NULL, "malloc");
    for(int i=0; i < frr_segs.size(); i++) {
        int ret = inet_pton(AF_INET6, frr_segs[frr_segs.size() - i - 1].c_str(), buf + sizeof(struct in6_addr)*i);
        CHECK(ret == 0, "Invalid segment given in FRR-SEGS");
    }

    std::stringstream segs;
    for(int i=0; i < buf_len; i++) {
        segs << std::to_string(buf[i]);
        if (i != buf_len-1)
            segs << ", ";
    }

    return fmt::format(BPF_PROGRAM_TPL, fmt::arg("entry_id", argv[5]),
                       fmt::arg("threshold", std::to_string(threshold_ns)),
                       fmt::arg("segments", segs.str()), 
                       fmt::arg("nseg", std::to_string(frr_segs.size() - 1)),
                       fmt::arg("hdrlen", std::to_string(frr_segs.size() * 2)));
}

int fill_maps(int entry_id, char *bfd_segments, int map_timers_fd, int map_assoc_fd)
{
    struct in6_addr hash_blk[NB_MAX_SEGS+1];
    memset(hash_blk, 0, sizeof(hash_blk));

    std::vector<std::string> bfd_segs = split_segments(bfd_segments);
    int ret = inet_pton(AF_INET6, bfd_segs[0].c_str(), &hash_blk[0]);
    CHECK(ret == 0, "Invalid segment given in BFD-SEGS");

    for(int i=1; i < bfd_segs.size(); i++) {
        /* we here reproduce the order of the segments in the SRH,
         * which is copied as-is by the BFD BPF program */
        ret = inet_pton(AF_INET6, bfd_segs[bfd_segs.size() - i].c_str(), &hash_blk[i]);
        CHECK(ret == 0, "Invalid segment given in BFD-SEGS");
    }

    struct bfd_entry entry = {0, 0, 0};
    ret = bpf_update_elem(map_assoc_fd, hash_blk, &entry_id, BPF_ANY);
    CHECK(ret, "Error updating BPF map sr6_bfd_assoc");
    ret = bpf_update_elem(map_timers_fd, &entry_id, &entry, BPF_ANY);
    CHECK(ret, "Error updating BPF map sr6_bfd_timers");
}

int main(int argc, char *argv[])
{
    if (argc < 7) {
        fmt::print(stderr, "Usage: {} PREFIX GATEWAY OIF FRR-SEGS TIMER-ID BFD-SEGS THRESHOLD\n", argv[0]);
        return -1;
    }

    uint32_t entry_id;
    uint64_t threshold;
    try {
        entry_id = std::stoi(argv[5]);
        threshold = (uint64_t) std::stoll(argv[7]);
        CHECK(entry_id < 0, "TIMER-ID should be positive");
        CHECK(threshold < 0, "THRESHOLD should be positive");
    } catch (std::exception const &e) {
        CHECK(1, "TIMER-ID and THRESHOLD must be valid integers");
    }

    std::string bpf_prog = build_prog(argv, threshold * 1000); // from microsec to nanosec
    std::cout << bpf_prog << std::endl;

    int map_timers_fd = bpf_obj_get("/sys/fs/bpf/ip/globals/sr6_bfd_timers");
    int map_assoc_fd = bpf_obj_get("/sys/fs/bpf/ip/globals/sr6_bfd_assoc");
    CHECK(map_timers_fd <= 0 || map_assoc_fd <= 0, "Could not fetch SRv6 BFD maps");

    fill_maps(entry_id, argv[6], map_timers_fd, map_assoc_fd);

    // populate map into TableStorage
    std::unique_ptr<ebpf::TableStorage> local_ts =
        ebpf::createSharedTableStorage();
    ebpf::Path global_path({"sr6_bfd_timers"});
    ebpf::TableDesc table_desc("sr6_bfd_timers", ebpf::FileDesc(map_timers_fd),
                             BPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
                             sizeof(struct bfd_entry), NB_TIMERS, 0);
    local_ts->Insert(global_path, std::move(table_desc));

    // constructor with the pre-populated table storage
    ebpf::BPF bpf(0, &*local_ts);
    auto res = bpf.init(bpf_prog);

    int prog_fd;
    res = bpf.load_func("frr", BPF_PROG_TYPE_LWT_IN, prog_fd);
    CHECK(res.code(), "Could not load BPF FRR program into the kernel");

    const char *prog_path = "/sys/fs/bpf/sr6_frr_tmp_prog";
    int err = bpf_obj_pin(prog_fd, prog_path);
    CHECK(err, "Could not pin BPF FRR program to " << prog_path);

    std::string cmd = fmt::format("ip -6 route add {} via {} dev {} encap bpf in pinned {}",
                                  argv[1], argv[2], argv[3], prog_path);
    std::cout << cmd << std::endl;
    std::system(cmd.c_str());

    std::remove(prog_path);
    return 0;
}
