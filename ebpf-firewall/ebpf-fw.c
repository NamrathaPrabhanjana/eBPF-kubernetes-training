
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/types.h>

/* Struct that describes a packet: srcip, dstip and flags (direction and whether it was blocked) */
typedef struct {
    u32 flags;
    u32 dstip;
    u32 srcip;
} conn;

/* Map for sending flow information (srcip, dstip, direction) to userspace */
BPF_QUEUE(flows_map, conn, 64);

/* Array for blocking IP addresses from userspace */
BPF_ARRAY(blocked_map, u32, 64);

/* Handle a packet: send its information to userspace and return whether it should be allowed */
static int handle_pkt(struct __sk_buff *skb, int egress) {
    struct iphdr *iph = (struct iphdr*)(skb->data + sizeof(struct ethhdr));
    // ensure ip hdr is within packet boundary
    if (((void *)(iph) + sizeof(*iph)) > (void*)(long)skb->data_end) {
        return 0;
    }
    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, iph, sizeof(struct iphdr));
    /* Check if IPs are in "blocked" map */
    int blocked = blocked_map.lookup(&(iph->saddr)) || blocked_map.lookup(&(iph->daddr));
    if (iph->version == 4) {
        conn c = {
            .flags = egress | (blocked << 1),
            .srcip = iph->saddr,
            .dstip = iph->daddr,
        };

        /* Send packet info to user program to display */
        bpf_map_push_elem(&flows_map, &c, 0);
    }
    /* Return whether it should be allowed or dropped */
    return !blocked;
}

/* Ingress hook - handle incoming packets */
int ingress_fn(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, 0);
}

/* Egress hook - handle outgoing packets */
int egress_fn(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, 1);
}

