#define SEC(name) __attribute__((section(name), used))
#define __ksym __attribute__((section(".ksyms")))

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;

struct xdp_md;
struct nf_conn;

struct bpf_sock_tuple {
    union {
        struct {
            u32 saddr;
            u32 daddr;
            u16 sport;
            u16 dport;
        } ipv4;
        struct {
            u32 saddr[4];
            u32 daddr[4];
            u16 sport;
            u16 dport;
        } ipv6;
    };
};

struct bpf_ct_opts {
    s32 netns_id;
    s32 error;
    u8 l4proto;
    u8 dir;
    u16 ct_zone_id;
    u8 ct_zone_dir;
    u8 reserved[3];
};

extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *context,
                                         struct bpf_sock_tuple *tuple,
                                         u32 tuple_size,
                                         struct bpf_ct_opts *options,
                                         u32 options_size) __ksym;
extern void bpf_ct_release(struct nf_conn *connection) __ksym;

SEC("xdp")
int call_module_kfunc(struct xdp_md *context)
{
    struct bpf_sock_tuple tuple = {};
    struct bpf_ct_opts options = {
        .netns_id = -1,
        .l4proto = 6,
    };
    struct nf_conn *connection;

    connection = bpf_xdp_ct_lookup(context, &tuple, sizeof(tuple.ipv4),
                                   &options, sizeof(options));
    if (connection)
        bpf_ct_release(connection);
    return 2;
}

char LICENSE[] SEC("license") = "GPL";
