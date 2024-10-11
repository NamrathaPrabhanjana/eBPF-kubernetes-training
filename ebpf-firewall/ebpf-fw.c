
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
BPF_QUEUE(flows_map, conn, 10000)

/* Map for blocking IP addresses from userspace */
BPF_HASH(blocked_map, u32, u32, 10000)

/* Handle a packet: send its information to userspace and return whether it should be allowed */
inline bool handle_pkt(struct __sk_buff *skb, bool egress) {
    struct iphdr iph;
    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
    /* Check if IPs are in "blocked" map */
    bool blocked = bpf_map_lookup_elem(&blocked_map, &iph.saddr) || bpf_map_lookup_elem(&blocked_map, &iph.daddr);
    if (iph.version == 4) {
        conn c = {
            .flags = egress | (blocked << 1),
            .srcip = iph.saddr,
            .dstip = iph.daddr,
        };

        /* Send packet info to user program to display */
        bpf_map_push_elem(&flows_map, &c, 0);
    }
    /* Return whether it should be allowed or dropped */
    return !blocked;
}

/* Ingress hook - handle incoming packets */
int ingress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, false);
}

/* Egress hook - handle outgoing packets */
int egress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, true);
}

