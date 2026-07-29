//! Prints the maps and programs found in an eBPF ELF object.

use std::env;
use std::error::Error;

use ebeepf::Object;

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: cargo run -p ebeepf --example inspect -- PROGRAM.bpf.o")?;
    let object = Object::open(path)?;

    println!("object: {} (license: {})", object.name(), object.license());
    for map in object.maps() {
        println!(
            "map: {} {:?}, key {}, value {}, entries {}",
            map.name(),
            map.map_type(),
            map.key_size(),
            map.value_size(),
            map.max_entries()
        );
    }
    for program in object.programs() {
        println!(
            "program: {} {:?}, {} instructions",
            program.name(),
            program.kind(),
            program.instructions().len()
        );
    }
    Ok(())
}
