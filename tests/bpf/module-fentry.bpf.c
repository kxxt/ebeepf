#define SEC(name) __attribute__((section(name), used))

SEC("fentry/dummy:dummy_xmit")
int observe_dummy_xmit(void *context)
{
    (void)context;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
