#define SEC(name) __attribute__((section(name), used))
#define __ksym __attribute__((section(".ksyms")))

typedef unsigned int u32;
typedef unsigned long long u64;

struct pt_regs;

extern const int bpf_prog_active __ksym;
extern void schedule(void) __ksym;
extern void dummy_xmit(void) __ksym;
extern const void jiffies __ksym;

static void *(*bpf_per_cpu_ptr)(const void *pointer, u32 cpu) = (void *)154;
static u64 (*bpf_get_func_ip)(void *context) = (void *)173;

SEC("socket")
int read_typed_kernel_variable(void *context)
{
    int *active;

    (void)context;
    active = bpf_per_cpu_ptr(&bpf_prog_active, 0);
    return active ? *active : 0;
}

SEC("kprobe.multi/schedule")
int compare_typed_kernel_function(struct pt_regs *context)
{
    return bpf_get_func_ip(context) == (u64)&schedule;
}

SEC("kprobe.multi/dummy_xmit")
int compare_typed_module_function(struct pt_regs *context)
{
    return bpf_get_func_ip(context) == (u64)&dummy_xmit;
}

SEC("socket")
int retain_typeless_kernel_symbol(void *context)
{
    (void)context;
    asm volatile("" : : "r"(&jiffies));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
