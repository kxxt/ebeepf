//! Lists function types exposed by a loaded kernel module's split BTF.

use std::env;
use std::error::Error;

use ebeepf::{BtfKind, BtfObject};

fn main() -> Result<(), Box<dyn Error>> {
    let module = env::args()
        .nth(1)
        .ok_or("usage: cargo run -p ebeepf --example btf_module -- MODULE")?;
    let btf = BtfObject::from_kernel_module(&module)?;
    println!(
        "{}: BTF ID {}, {} combined types",
        btf.info().name,
        btf.info().id,
        btf.btf().len()
    );
    for (id, ty) in btf.btf().types() {
        if id.0 as usize > btf.btf().base_type_count() && ty.kind() == BtfKind::Function {
            if let Some(name) = ty.name() {
                println!("{} {name}", id.0);
            }
        }
    }
    Ok(())
}
