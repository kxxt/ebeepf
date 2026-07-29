//! Loads an eBPF object and prints kernel-assigned resource IDs.

use std::env;
use std::error::Error;

use ebeepf::Object;

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: cargo run -p ebeepf --example load -- PROGRAM.bpf.o")?;
    let object = Object::open(path)?.load()?;
    for map in object.maps() {
        println!("map {}: kernel ID {}", map.name(), map.info()?.id);
    }
    for program in object.programs() {
        println!(
            "program {}: kernel ID {}",
            program.name(),
            program.info()?.id
        );
    }
    Ok(())
}
