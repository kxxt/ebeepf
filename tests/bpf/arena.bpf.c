#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __concat(left, right) left##right
#define __concat_value(left, right) __concat(left, right)
#define __ulong(name, value) \
    enum { __concat_value(unique_value_, __COUNTER__) = value } name
#define __arena __attribute__((address_space(1)))

enum {
    BPF_MAP_TYPE_ARENA = 33,
    BPF_F_MMAPABLE = 1U << 10,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 8);
    __ulong(map_extra, 1ULL << 44);
} arena SEC(".maps");

unsigned int __arena arena_value = 41;

SEC("socket")
int read_arena_global(void *context)
{
    (void)context;
    return arena_value;
}

char LICENSE[] SEC("license") = "GPL";
