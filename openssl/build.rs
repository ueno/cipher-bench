extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=bindings/evp.h");

    let bindings = bindgen::Builder::default()
        .header("bindings/evp.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_inline_functions(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("evp.rs"))
        .expect("Couldn't write bindings!");
}
