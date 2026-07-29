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

struct shared_map_definition linked_shared_map SEC(".maps");
