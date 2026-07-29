//! Lists `SystemTap` USDT probes in an ELF executable or shared object.

use std::env;
use std::error::Error;

use ebeepf::discover_usdt_probes;

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: cargo run -p ebeepf --example usdt -- EXECUTABLE")?;
    for probe in discover_usdt_probes(path)? {
        println!(
            "{}:{} offset=0x{:x} semaphore={:?} args={}",
            probe.provider, probe.name, probe.offset, probe.semaphore_offset, probe.arguments
        );
    }
    Ok(())
}
