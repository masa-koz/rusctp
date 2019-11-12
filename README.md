rusctp is an implementation of the Stream Control Transmission Protocol (SCTP) as specified by the IETF.

Building
--------

rusctp requires Rust 1.38 or later to build. You can install the latest stable Rust release using [rustup](https://rustup.rs/).

Once the Rust build environment is setup, you can fetch the rusctp source code using git:

```bash
 $ git clone https://github.com/masa-koz/rusctp.git
```

and then built using cargo:

```bash
 $ cargo build --examples
```