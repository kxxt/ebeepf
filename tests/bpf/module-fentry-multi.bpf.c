#define SEC(name) __attribute__((section(name), used))

SEC("fentry.multi/dummy:dummy_*")
int observe_dummy_functions(void *context)
{
    (void)context;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
