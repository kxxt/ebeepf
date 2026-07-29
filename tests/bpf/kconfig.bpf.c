#define SEC(name) __attribute__((section(name), used))
#define __kconfig __attribute__((section(".kconfig")))

enum libbpf_tristate {
    TRI_NO,
    TRI_MODULE,
    TRI_YES,
};

extern unsigned int CONFIG_HZ __kconfig;
extern _Bool CONFIG_PREEMPT_DYNAMIC __kconfig;
extern enum libbpf_tristate CONFIG_VFAT_FS __kconfig;
extern char CONFIG_LOCALVERSION[64] __kconfig;
extern unsigned int LINUX_KERNEL_VERSION __kconfig;
extern _Bool LINUX_HAS_BPF_COOKIE __kconfig;
extern _Bool LINUX_HAS_SYSCALL_WRAPPER __kconfig;

SEC("socket")
int consume_kernel_configuration(void *context)
{
    (void)context;
    return CONFIG_HZ + CONFIG_PREEMPT_DYNAMIC + CONFIG_VFAT_FS
        + CONFIG_LOCALVERSION[0] + LINUX_KERNEL_VERSION
        + LINUX_HAS_BPF_COOKIE + LINUX_HAS_SYSCALL_WRAPPER;
}

char LICENSE[] SEC("license") = "GPL";
