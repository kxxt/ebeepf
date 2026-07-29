#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

typedef unsigned int __u32;
struct __sk_buff;

struct {
    __uint(type, 15);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} sockets SEC(".maps");

SEC("sk_skb/stream_parser")
int parse_message(struct __sk_buff *context)
{
    (void)context;
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
