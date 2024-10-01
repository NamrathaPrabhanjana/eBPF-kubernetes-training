#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>

struct data_t {
	u32 pid;
	u64 enqueue_time;
	u64 latency;
	char comm[TASK_COMM_LEN];
};

// Hashmap to store enqueued for each task by its pid
BPF_HASH(runqueue, u32, u64);

// Perf buffer to send data to user space
BPF_PERF_OUTPUT(events);

// Attach to sched_enqueue_task tracepoint
int trace_sched_enqueue_task(struct pt_regs *ctx, struct task_struct *task) {
	u32 pid = task->pid;
	u64 enqueue_time = bpf_ktime_get_ns();
	runqueue.update(&pid, &enqueue_time);
	return 0;
}

// Attach to the sched_switch tracepoint
int trace_sched_switch(struct pt_regs *ctx, struct task_struct *prev) {
	u32 pid = prev->pid;
	u64 *enqueue_time = runqueue.lookup(&pid);
	if (enqueue_time != NULL) {
		struct data_t data = {};
		data.pid = pid;
		data.enqueue_time = *enqueue_time;
		data.latency = bpf_ktime_get_ns() - *enqueue_time;
		bpf_get_current_comm(&data.comm, sizeof(data.comm));
		events.perf_submit(ctx, &data, sizeof(data));
		runqueue.delete(&pid);
	}
	return 0;
}

// Attach to the sched_process_exit tracepoint
int trace_sched_process_exit(struct pt_regs *ctx, struct task_struct *task) {
	u32 pid = task->pid;
	runqueue.delete(&pid);
	return 0;
}

// When are these tracepoints called?
// sched_enqueue_task: When a task is enqueued to the runqueue
// sched_switch: When a task is switched out from the CPU
// sched_process_exit: When a task exits
