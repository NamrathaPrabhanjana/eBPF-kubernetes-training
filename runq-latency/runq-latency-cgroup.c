// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>

// Structure to store cgroup statistics.
struct cgroup_stats {
    u64 cpu_time_ns;  // CPU time used in nanoseconds.
    u64 mem_usage_bytes; // Memory usage in bytes.
};

// BPF map to store cgroup statistics.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);            // Cgroup ID as the key.
    __type(value, struct cgroup_stats); // Stats as the value.
    __uint(max_entries, 1024);    // Maximum number of cgroup entries.
} cgroup_stats_map SEC(".maps");

// BPF map to store the timestamp of the last CPU scheduling event for a cgroup.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);  // Cgroup ID as the key.
    __type(value, u64); // Timestamp as the value.
    __uint(max_entries, 1024);
} cgroup_start_time_map SEC(".maps");

// Helper function to get cgroup ID of the current task.
static __inline u64 get_current_cgroup_id() {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    return task->cgroups->dfl_cgrp->kn->id;
}

// Tracepoint for process scheduling switch.
// Tracks CPU time per cgroup.
int trace_sched_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u32 prev_pid = ctx->prev_pid;  // Previous (outgoing) PID.
    u32 next_pid = ctx->next_pid;  // Next (incoming) PID.

    // Get current timestamp.
    u64 ts = bpf_ktime_get_ns();

    // Get cgroup ID of the previous process.
    u64 prev_cgroup_id = get_current_cgroup_id();

    // Track CPU usage for the previous cgroup.
    u64 *start_time = bpf_map_lookup_elem(&cgroup_start_time_map, &prev_cgroup_id);
    if (start_time) {
        // Calculate CPU time used by the previous cgroup.
        u64 delta = ts - *start_time;

        // Update cgroup statistics in the cgroup_stats_map.
        struct cgroup_stats *stats = bpf_map_lookup_elem(&cgroup_stats_map, &prev_cgroup_id);
        if (stats) {
            stats->cpu_time_ns += delta;
        } else {
            struct cgroup_stats new_stats = {0};
            new_stats.cpu_time_ns = delta;
            bpf_map_update_elem(&cgroup_stats_map, &prev_cgroup_id, &new_stats, BPF_ANY);
        }
    }

    // Update the start time for the next cgroup being scheduled in.
    u64 next_cgroup_id = get_current_cgroup_id();
    bpf_map_update_elem(&cgroup_start_time_map, &next_cgroup_id, &ts, BPF_ANY);

    return 0;
}

// Cgroup hook for memory usage monitoring.
// Attaches to cgroup memory events.
/*
SEC("cgroup/memcg/memcg_stat")
int mem_usage_monitor(struct bpf_sock_ops *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    // Get current memory usage in bytes.
    u64 mem_usage = bpf_memcg_stat(); // Get the current memory usage of the cgroup.

    // Update memory usage in the cgroup_stats_map.
    struct cgroup_stats *stats = bpf_map_lookup_elem(&cgroup_stats_map, &cgroup_id);
    if (stats) {
        stats->mem_usage_bytes = mem_usage;
    } else {
        struct cgroup_stats new_stats = {0};
        new_stats.mem_usage_bytes = mem_usage;
        bpf_map_update_elem(&cgroup_stats_map, &cgroup_id, &new_stats, BPF_ANY);
    }

    return 0;
}

*/

// I am unable to compile this program with clang. It complains that types u32 and u64 are not defined.
// I am not sure how to fix this issue. I have tried to include the necessary headers but it still does not work.
// do you know how to fix this?
// I have also tried to compile this program with the following command:
// clang -O2 -target bpf -c runq-latency-cgroup.c -o runq-latency-cgroup.o
// but it still does not work.