#define SEC(name) __attribute__((section(name), used))

struct __sk_buff;

__attribute__((noinline))
int replaceable(int value)
{
    return value + 1;
}

SEC("xdp")
int call_replaceable(struct __sk_buff *context)
{
    (void)context;
    return replaceable(1);
}

char LICENSE[] SEC("license") = "GPL";
