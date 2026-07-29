//! Command-line interface for Rust-native eBPF skeleton generation.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use ebeepf::SkeletonBuilder;

fn usage() -> &'static str {
    "Usage:\n  ebeepf-skel generate <INPUT.bpf.o> <OUTPUT.rs> [--name NAME] [--reference]\n  ebeepf-skel build <INPUT.bpf.c> <OUTPUT.bpf.o> <OUTPUT.rs> [--clang PATH] [--reference] [-- <CLANG_ARGS>...]"
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ebeepf-skel: {error}\n\n{}", usage());
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<(), String> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Err("missing command".into());
    };
    match command {
        "generate" => generate(&arguments[1..]),
        "build" => build(&arguments[1..]),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        value => Err(format!("unknown command `{value}`")),
    }
}

fn generate(arguments: &[OsString]) -> Result<(), String> {
    if arguments.len() < 2 {
        return Err("generate needs an input object and output Rust path".into());
    }
    let object = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    let mut builder = SkeletonBuilder::new();
    builder.object(object);
    let mut index = 2;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--reference") => {
                builder.reference_object(true);
                index += 1;
            }
            Some("--name") if index + 1 < arguments.len() => {
                builder.name(arguments[index + 1].to_string_lossy());
                index += 2;
            }
            Some(value) => return Err(format!("unknown generate option `{value}`")),
            None => return Err("generate option is not UTF-8".into()),
        }
    }
    builder.generate(output).map_err(|error| error.to_string())
}

fn build(arguments: &[OsString]) -> Result<(), String> {
    if arguments.len() < 3 {
        return Err("build needs a source, object output, and Rust output".into());
    }
    let source = PathBuf::from(&arguments[0]);
    let object = PathBuf::from(&arguments[1]);
    let output = PathBuf::from(&arguments[2]);
    let mut builder = SkeletonBuilder::new();
    builder.source(source).object(object);
    let mut clang_args = Vec::new();
    let mut index = 3;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--reference") => {
                builder.reference_object(true);
                index += 1;
            }
            Some("--clang") if index + 1 < arguments.len() => {
                builder.clang(&arguments[index + 1]);
                index += 2;
            }
            Some("--") => {
                clang_args.extend_from_slice(&arguments[index + 1..]);
                break;
            }
            Some(value) => return Err(format!("unknown build option `{value}`")),
            None => return Err("build option is not UTF-8".into()),
        }
    }
    builder.clang_args(clang_args);
    builder
        .build_and_generate(output)
        .map_err(|error| error.to_string())
}
