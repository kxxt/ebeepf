#define SEC(name) __attribute__((section(name), used))

struct zcomp_params {
    unsigned int algorithm;
} __attribute__((preserve_access_index));

SEC("socket")
int module_type_exists(void *context)
{
    (void)context;
    return __builtin_preserve_type_info(*(struct zcomp_params *)0, 0);
}

char LICENSE[] SEC("license") = "GPL";
