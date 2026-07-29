#define SEC(name) __attribute__((section(name), used))

extern int linked_subprogram(int value);

SEC("socket")
int linked_entry(void *context)
{
    (void)context;
    return linked_subprogram(40);
}

char LICENSE[] SEC("license") = "GPL";
