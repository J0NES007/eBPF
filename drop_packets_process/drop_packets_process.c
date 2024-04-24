
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <bpf/bpf_core_read.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <net/sock.h>


#define PORT_MAP_SIZE 1
#define MAX_PROCESS_NAME_LEN 16
#define TASK_COMM_LEN 16

// Define an eBPF map to store the port number
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, PORT_MAP_SIZE);
} bpf_port_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, char[MAX_PROCESS_NAME_LEN]);
    __uint(max_entries, 1024);
} port_map SEC(".maps");


SEC("kprobe/inet_bind")
int bindprobe_entry(struct pt_regs *ctx, struct socket *sock, 
                        struct sockaddr *addr, int addrlen)
{
    // cast types. Intermediate cast not needed, kept for readability
    struct sock *sk = sock->sk;
    u16 family = sk->__sk_common.skc_family;
     if (family == AF_INET) {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        bpf_printk("Process Port: %s\n", ntohs(in_addr->sin_port));
     }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("Process Name: %s\n", comm);
    

    return 0;
}

// Drop packets that are headed to the specified destination port
SEC("xdp") 
int drop_packets(struct xdp_md *ctx) {
    bpf_printk("packet...\n");
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

    int *port = bpf_map_lookup_elem(&bpf_port_map, &(int){0});
    if (!port) {
        bpf_printk("Port map lookup failed\n");
        return XDP_PASS;
    }

    if (ntohs(tcp->dest) == *port) {
		bpf_printk("dropping packet on port: %d\n", ntohs(tcp->dest));
        return XDP_DROP; 
	}
    return XDP_PASS;

}

char __license[] SEC("license") = "Dual MIT/GPL";
