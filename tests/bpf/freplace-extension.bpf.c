#define SEC(name) __attribute__((section(name), used))

SEC("freplace/replaceable")
int replacement(int value)
{
    return value + 2;
}

char LICENSE[] SEC("license") = "GPL";
