#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/icmp.h>
#include <linux/in.h>

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
    bpf_trace_printk("Processed packet protocol lookup\n");
    return protocol;
}

int xdp_icmp_blocker_old(struct xdp_md *ctx)
{
    unsigned char protocol = lookup_protocol(ctx);
    if (protocol == UDP_PROTOCOL) {
        bpf_trace_printk("Dropping ICMP packet\n");
        return XDP_DROP;
    }
    return XDP_PASS;
}

int xdp_icmp_blocker(struct xdp_md *ctx)
{
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	
	if ((void*)eth + sizeof(*eth) <= data_end)
	{
		struct iphdr *ip = data + sizeof(*eth);
		if ((void*)ip + sizeof(*ip) <= data_end)
		{
			if (ip->protocol == IPPROTO_ICMP)
			{
				struct icmphdr *icmp = (void*)ip + sizeof(*ip);
				if ((void*)icmp + sizeof(*icmp) <= data_end)
				{
					bpf_trace_printk("Dropping ICMP packets\n");
					return XDP_DROP;
				}
			}
		}
	}

	return XDP_PASS;

}
