//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#define PORT_MAP_SIZE 1000

// Define an eBPF map to store the port number
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, char[6]);
        __uint(max_entries, PORT_MAP_SIZE);
} bpf_port_map SEC(".maps");


// Define an eBPF map to store the port to process mappings
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, PORT_MAP_SIZE);
} process_map SEC(".maps");


// Drop packets that are headed to the specified destination port
SEC("xdp") 
int drop_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
                bpf_printk("not enough data for ethernet header\n");
        return XDP_PASS;
        }

    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS; 
        }
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
                bpf_printk("Not enough data for IP header\n");
        return XDP_PASS;
        }

    if (ip->protocol == IPPROTO_TCP) {
        return XDP_PASS; 
        }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) {
                bpf_printk("not enough data for tcp header\n");
        return XDP_PASS;
        }

    
    __u16 port = ntohs(tcp->dest);
    __u32 key = (__u32)port;

    bpf_printk("packet on port: %d\n", ntohs(tcp->dest));

    char *expected_process_name; 
    // Get the expected process name
    expected_process_name = bpf_map_lookup_elem(&bpf_port_map, &key);
    if (!expected_process_name) {
        return XDP_PASS;
    } 
    bpf_printk("expected process namet: %c\n", expected_process_name);
    char *actual_process_name; 
    // Look up the process name in the process_map to see if the expected process is running on same port
    actual_process_name = bpf_map_lookup_elem(&process_map, &key);
    if (!actual_process_name) {
        return XDP_PASS;
    } 
    bpf_printk("actual process namet: %c\n", actual_process_name);
    // If the process name matches, then drop the packet for this port
    if (expected_process_name == actual_process_name) {
        bpf_printk("dropping packet for process: %c", actual_process_name);
        return XDP_DROP;
    }

    return XDP_PASS;

}

char __license[] SEC("license") = "Dual MIT/GPL";