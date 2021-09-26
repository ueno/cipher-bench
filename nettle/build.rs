// SPDX-License-Identifier: Apache-2.0

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=nettle");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    for name in ["block", "aead"] {
        println!("cargo:rerun-if-changed=bindings/{}.h", name);

        let bindings = bindgen::Builder::default()
            .header(format!("bindings/{}.h", name))
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect(&format!("Unable to generate {} bindings", name));

        bindings
            .write_to_file(out_path.join(format!("{}.rs", name)))
            .expect("Couldn't write bindings!");
    }
}
