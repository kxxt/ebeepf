typedef unsigned int __u32;

#define SEC(name) __attribute__((section(name), used))

struct sock;
struct rate_sample;

/*
 * A deliberately minimal CO-RE-style shadow of the kernel type. The loader
 * matches members by BTF name and builds the complete kernel wrapper value.
 */
struct tcp_congestion_ops {
    char name[16];
    void (*init)(struct sock *sk);
    void (*cong_control)(struct sock *sk, const struct rate_sample *sample);
    __u32 (*ssthresh)(struct sock *sk);
    __u32 (*undo_cwnd)(struct sock *sk);
};

SEC("struct_ops/ebeepf_ca_init")
void ebeepf_ca_init(struct sock *sk)
{
    (void)sk;
}

SEC("struct_ops/ebeepf_ca_cong_control")
void ebeepf_ca_cong_control(struct sock *sk, const struct rate_sample *sample)
{
    (void)sk;
    (void)sample;
}

SEC("struct_ops/ebeepf_ca_ssthresh")
__u32 ebeepf_ca_ssthresh(struct sock *sk)
{
    (void)sk;
    return 2;
}

SEC("struct_ops/ebeepf_ca_undo_cwnd")
__u32 ebeepf_ca_undo_cwnd(struct sock *sk)
{
    (void)sk;
    return 2;
}

SEC(".struct_ops.link")
struct tcp_congestion_ops ebeepf_ca = {
    .name = "ebeepf_ca",
    .init = (void *)ebeepf_ca_init,
    .cong_control = (void *)ebeepf_ca_cong_control,
    .ssthresh = (void *)ebeepf_ca_ssthresh,
    .undo_cwnd = (void *)ebeepf_ca_undo_cwnd,
};

SEC(".struct_ops")
struct tcp_congestion_ops ebeepf_legacy_ca = {
    .name = "ebeepf_legacy",
    .init = (void *)ebeepf_ca_init,
    .cong_control = (void *)ebeepf_ca_cong_control,
    .ssthresh = (void *)ebeepf_ca_ssthresh,
    .undo_cwnd = (void *)ebeepf_ca_undo_cwnd,
};

char LICENSE[] SEC("license") = "GPL";
