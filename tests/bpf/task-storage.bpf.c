#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define __ksym __attribute__((section(".ksyms")))

typedef unsigned int __u32;
typedef unsigned long long __u64;

extern void schedule(void) __ksym;

struct {
    __uint(type, 29);
    __uint(max_entries, 0);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, 1);
} task_values SEC(".maps");

SEC("socket")
int preserve_ksym(void *context)
{
    (void)context;
    asm volatile("" : : "r"(&schedule));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
