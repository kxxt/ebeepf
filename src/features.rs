use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;

use crate::object::{read_kernel_config, running_kernel_version};

/// eBPF-relevant capabilities of the running Linux kernel.
///
/// These values combine kernel configuration, architecture, and release
/// information where Linux does not expose a direct `bpf(2)` capability
/// probe. Missing kernel configuration is handled conservatively according to
/// each feature's compatibility requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelFeatures {
    compat_syscalls: bool,
    ftrace_direct_calls: bool,
    sleepable_fentry: bool,
    sleepable_hash_no_prealloc: bool,
    syscall_wrappers: bool,
    syscall_wrapper_kprobes: bool,
}

impl KernelFeatures {
    /// Probes eBPF-relevant capabilities of the running kernel.
    ///
    /// Kernel configuration is read from the same standard locations used for
    /// `.kconfig` extern resolution. If it is unavailable, release and
    /// architecture fallbacks are used.
    pub fn probe() -> Self {
        let config = read_kernel_config().ok().flatten();
        Self::from_parts(
            env::consts::ARCH,
            Some(running_kernel_version()).filter(|version| *version != 0),
            config.as_ref(),
        )
    }

    /// Whether the architecture exposes compatibility-mode syscall hooks.
    ///
    /// When kernel configuration is unavailable this defaults to `true`,
    /// allowing an object loader to try the compatibility programs.
    pub const fn compat_syscalls(self) -> bool {
        self.compat_syscalls
    }

    /// Whether BPF trampoline attachment can use fentry/fexit direct calls.
    pub const fn ftrace_direct_calls(self) -> bool {
        self.ftrace_direct_calls
    }

    /// Whether sleepable fentry programs are usable for functions that permit
    /// error injection.
    pub const fn sleepable_fentry(self) -> bool {
        self.sleepable_fentry
    }

    /// Whether sleepable programs can access hash maps created with
    /// `BPF_F_NO_PREALLOC`.
    pub const fn sleepable_hash_no_prealloc(self) -> bool {
        self.sleepable_hash_no_prealloc
    }

    /// Whether syscall entry points use architecture syscall wrappers.
    pub const fn syscall_wrappers(self) -> bool {
        self.syscall_wrappers
    }

    /// Whether ordinary kprobes can attach to syscall wrapper entry points.
    pub const fn syscall_wrapper_kprobes(self) -> bool {
        self.syscall_wrapper_kprobes
    }

    fn from_parts(
        architecture: &str,
        version: Option<u32>,
        config: Option<&HashMap<String, String>>,
    ) -> Self {
        let at_least =
            |major, minor| version.is_some_and(|version| version >= encoded_version(major, minor));
        let enabled = |name| config.is_some_and(|config| config_enabled(config, name));

        let syscall_wrappers = match architecture {
            "riscv64" => enabled("CONFIG_ARCH_HAS_SYSCALL_WRAPPER") || at_least(6, 6),
            _ => true,
        };
        let syscall_wrapper_kprobes = match (architecture, config) {
            ("riscv64", Some(config)) => {
                !(syscall_wrappers
                    && config_enabled(config, "CONFIG_DYNAMIC_FTRACE")
                    && !config_enabled(config, "CONFIG_KPROBES_ON_FTRACE"))
            }
            _ => true,
        };
        let ftrace_direct_calls = enabled("CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS")
            || match architecture {
                "x86_64" => true,
                "aarch64" => at_least(6, 4),
                "riscv64" => at_least(6, 8),
                _ => false,
            };

        Self {
            compat_syscalls: config
                .map(|config| config_enabled(config, "CONFIG_IA32_EMULATION"))
                .unwrap_or(true),
            ftrace_direct_calls,
            sleepable_fentry: config
                .map(|config| config_enabled(config, "CONFIG_FUNCTION_ERROR_INJECTION"))
                .unwrap_or(true),
            sleepable_hash_no_prealloc: at_least(6, 1),
            syscall_wrappers,
            syscall_wrapper_kprobes,
        }
    }
}

/// Returns the number of CPUs that the running kernel can bring online.
///
/// This follows Linux's possible-CPU list rather than the process affinity
/// mask, which is the correct sizing basis for per-CPU BPF resources.
pub fn possible_cpu_count() -> io::Result<usize> {
    let contents = fs::read_to_string("/sys/devices/system/cpu/possible")?;
    parse_cpu_list(&contents)
}

fn config_enabled(config: &HashMap<String, String>, name: &str) -> bool {
    config
        .get(name)
        .is_some_and(|value| matches!(value.as_str(), "y" | "m"))
}

const fn encoded_version(major: u32, minor: u32) -> u32 {
    (major << 16) | (minor << 8)
}

fn parse_cpu_list(contents: &str) -> io::Result<usize> {
    let mut count = 0_usize;
    for item in contents.trim().split(',') {
        let (first, last) = item
            .split_once('-')
            .map_or((item, item), |(first, last)| (first, last));
        let first = first
            .parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid possible-CPU list"))?;
        let last = last
            .parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid possible-CPU list"))?;
        let range = last
            .checked_sub(first)
            .and_then(|range| range.checked_add(1))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid possible-CPU range")
            })?;
        count = count.checked_add(range).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "possible-CPU count overflow")
        })?;
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "possible-CPU list is empty",
        ));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::parse_kernel_version;

    fn config(names: &[&str]) -> HashMap<String, String> {
        names
            .iter()
            .map(|name| ((*name).into(), "y".into()))
            .collect()
    }

    #[test]
    fn x86_features_use_architecture_and_configuration() {
        let features = KernelFeatures::from_parts(
            "x86_64",
            parse_kernel_version("5.17.0"),
            Some(&config(&[
                "CONFIG_IA32_EMULATION",
                "CONFIG_FUNCTION_ERROR_INJECTION",
            ])),
        );
        assert!(features.compat_syscalls());
        assert!(features.ftrace_direct_calls());
        assert!(features.sleepable_fentry());
        assert!(!features.sleepable_hash_no_prealloc());
        assert!(features.syscall_wrappers());
        assert!(features.syscall_wrapper_kprobes());
    }

    #[test]
    fn missing_configuration_uses_compatible_defaults() {
        let features = KernelFeatures::from_parts("aarch64", parse_kernel_version("6.4.0"), None);
        assert!(features.compat_syscalls());
        assert!(features.ftrace_direct_calls());
        assert!(features.sleepable_fentry());
        assert!(features.sleepable_hash_no_prealloc());
    }

    #[test]
    fn riscv_wrapper_kprobes_respect_ftrace_configuration() {
        let features = KernelFeatures::from_parts(
            "riscv64",
            parse_kernel_version("6.8.0"),
            Some(&config(&[
                "CONFIG_ARCH_HAS_SYSCALL_WRAPPER",
                "CONFIG_DYNAMIC_FTRACE",
            ])),
        );
        assert!(features.syscall_wrappers());
        assert!(!features.syscall_wrapper_kprobes());

        let features = KernelFeatures::from_parts(
            "riscv64",
            parse_kernel_version("6.8.0"),
            Some(&config(&[
                "CONFIG_ARCH_HAS_SYSCALL_WRAPPER",
                "CONFIG_DYNAMIC_FTRACE",
                "CONFIG_KPROBES_ON_FTRACE",
            ])),
        );
        assert!(features.syscall_wrapper_kprobes());
    }

    #[test]
    fn disabled_configuration_values_are_not_features() {
        let config = HashMap::from([
            ("CONFIG_IA32_EMULATION".into(), "n".into()),
            ("CONFIG_FUNCTION_ERROR_INJECTION".into(), "n".into()),
        ]);
        let features =
            KernelFeatures::from_parts("x86_64", parse_kernel_version("6.1.0"), Some(&config));
        assert!(!features.compat_syscalls());
        assert!(!features.sleepable_fentry());
    }

    #[test]
    fn possible_cpu_lists_count_ranges_and_singletons() {
        assert_eq!(parse_cpu_list("0-3,8,10-11\n").unwrap(), 7);
        assert!(parse_cpu_list("3-1").is_err());
        assert!(parse_cpu_list("").is_err());
    }
}
