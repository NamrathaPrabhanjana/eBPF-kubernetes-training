// Write a C program to detect noisy neighbour using eBPF

// The program should use the sched_switch endpoint to detect when a process is scheduled in or out

// The program should calculate the time a process spends in the runqueue
// And also monitor cpu and memory usage of the process based on cgroup

// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>
#include <linux/ptrace.h>

struct key_t {
    u32 pid;
    char comm[16];
};

// Map to track per-process CPU usage time.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, u64);
    __uint(max_entries, 1024);
} cpu_usage_map SEC(".maps");

// This map tracks the timestamp when the process was last scheduled in.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // PID as the key
    __type(value, u64); // Timestamp as the value
    __uint(max_entries, 1024);
} start_time_map SEC(".maps");

// Tracepoint for process scheduling switch.
// Triggered every time a process is scheduled in/out.
SEC("tracepoint/sched/sched_switch")
int sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u32 prev_pid = ctx->prev_pid; // Previous (outgoing) PID
    u32 next_pid = ctx->next_pid; // Next (incoming) PID

    // Get current timestamp.
    u64 ts = bpf_ktime_get_ns();

    // Track CPU usage for the previous process.
    u64 *start_time = bpf_map_lookup_elem(&start_time_map, &prev_pid);
    if (start_time) {
        // Calculate CPU time used by the previous process.
        u64 delta = ts - *start_time;

        // Create a key for the previous process.
        struct key_t key = {};
        key.pid = prev_pid;
        bpf_get_current_comm(&key.comm, sizeof(key.comm));

        // Update CPU usage time in the cpu_usage_map.
        u64 *usage = bpf_map_lookup_elem(&cpu_usage_map, &key);
        if (usage) {
            *usage += delta;
        } else {
            bpf_map_update_elem(&cpu_usage_map, &key, &delta, BPF_ANY);
        }
    }

    // Update the start time for the next process being scheduled in.
    bpf_map_update_elem(&start_time_map, &next_pid, &ts, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
