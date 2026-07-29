//! Temporarily exercises CO-RE relocation against the running kernel.

use std::env;
use std::error::Error;

use ebeepf::Object;

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args_os().nth(1).ok_or("missing object path")?;
    let mut object = Object::open(path)?;
    object.relocate_for_running_kernel()?;
    for program in object.programs() {
        println!("{:?}", program.instructions());
    }
    Ok(())
}
