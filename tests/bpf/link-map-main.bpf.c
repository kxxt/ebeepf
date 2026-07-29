#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

typedef unsigned int u32;
typedef unsigned long long u64;

struct shared_map_definition {
    __uint(type, 2);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
};

extern struct shared_map_definition linked_shared_map __attribute__((section(".maps")));

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

SEC("socket")
int linked_map_entry(void *context)
{
    u32 key = 0;
    u64 *value;

    (void)context;
    value = bpf_map_lookup_elem(&linked_shared_map, &key);
    return value ? (int)*value : -1;
}

char LICENSE[] SEC("license") = "GPL";
