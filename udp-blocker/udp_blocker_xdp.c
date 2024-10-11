#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define ETH_P_IP 0x0800
#define ICMP_PROTOCOL 1
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

//Return the protocol byte for an IP packet, 0 otherwise
static inline unsigned char lookup_protocol(struct xdp_md *ctx)
{
    unsigned char protocol = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return 0;
    }

    //Check if it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end) {
            protocol = iph->protocol;
        }
    }
    return protocol;
}

int xdp_udp_blocker(struct xdp_md *ctx)
{
    unsigned char protocol = lookup_protocol(ctx);
    if (protocol == ICMP_PROTOCOL) {
        bpf_trace_printk("Dropping UDP packet\n");
        return XDP_DROP;
    }
    return XDP_PASS;
}
