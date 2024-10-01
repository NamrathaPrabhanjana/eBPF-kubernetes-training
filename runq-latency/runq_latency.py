from bcc import BPF
import sys
from time import sleep

# Attach the bpf program
b = BPF(src_file="runq_latency.c")
#b.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
b.attach_tracepoint(tp="sched:sched_enqueue_task", fn_name="trace_sched_enqueue_task")
b.attach_tracepoint(tp="sched:sched_process_exit", fn_name="trace_sched_process_exit")

# define the callback for perf buffer
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("PID: %d, comm: %s, runq latency: %d" % (event.pid, event.comm, event.latency))

b["events"].open_perf_buffer(print_event)
print("Tracing runq latency...")
# loop with callback to print_event
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting...")
    sys.exit(0)
except Exception as e: 
    print(str(e))
