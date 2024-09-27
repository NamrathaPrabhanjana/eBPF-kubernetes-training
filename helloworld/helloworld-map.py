#! /usr/bin/python3

from bcc import BPF
from time import sleep

program = r"""
#include <linux/types.h>

BPF_HASH(counter_table);

int hello(void *ctx)
{
    u64 uid;
    u64 counter = 0;
    u64 *p;
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table.lookup(&uid);
    if (p) {
        counter = *p;
    }
    counter += 1;
    counter_table.update(&uid, &counter);
    bpf_trace_printk("Hello World\n");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += "ID {0}: {1}\n".format(k.value, v.value)
    print (s)


