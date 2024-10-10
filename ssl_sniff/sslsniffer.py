# Write a python program similar to the sslsniff.py program that listens for incoming SSL connections and tracks SSL_read() and SSL_write() functions. Use eBPF for attaching uprobes.

from bcc import BPF
import sys

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_BUF_SIZE 1024

// Define the struct that will be sent to user space
struct data_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    u32 len;
    char buf[MAX_BUF_SIZE];
};

BPF_PERF_OUTPUT(events);

// Helper function to submit SSL_read() data
int probe_ssl_read(struct pt_regs *ctx, void *ssl, void *buf, int ret) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (ret > MAX_BUF_SIZE) {
        data.len = MAX_BUF_SIZE;
    } 
    
    if (buf != NULL) {
        ret = bpf_probe_read_user(&data.buf, sizeof(data.buf), buf);
    }
    data.len = (ret > MAX_BUF_SIZE) ? MAX_BUF_SIZE : ret;
    event.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Helper function to submit SSL_write() data
int probe_ssl_write(struct pt_regs *ctx, void *ssl, void *buf, int ret) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (buf != NULL) {
        bpf_probe_read_user(&data.buf, sizeof(data.buf), buf);
    }
    data.len = (ret > MAX_BUF_SIZE) ? MAX_BUF_SIZE : ret;
    event.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print ("PID: %d, COMM: %s, TIMESTAMP: %d, LEN: %d, BUF: %s\n" % (event.pid, event.comm, event.timestamp, event.len, event.buf))

bpf = BPF(text=bpf_text)
libssl = "/usr/lib/aarch64-linux-gnu/libssl.so.1.1"
bpf.attach_uprobe(name=libssl, sym="SSL_read", fn_name="probe_ssl_read")
bpf.attach_uprobe(name=libssl, sym="SSL_write", fn_name="probe_ssl_write")

print("Tracing SSL connections...")

bpf["events"].open_perf_buffer(print_event)

try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching uprobe...")
    sys.exit(0)