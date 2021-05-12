# MPCD

`mpcd` is a Rust implementation of a service that intermediates communication among different clients running multiparty protocol implementations. `mpcd` can now interact with smartcards via PC/SC interface and contains internal implementations of several multiparty protocols.

## Supported protocols

Currently, `mpcd` supports distributed key generation and multiple approaches to Schnorr signing.

### Key Generation

- KeygenCommit (smartcard, simulated)

### Schnorr Signing

- NonceExchange (smartcard, simulated)
- NonceCommit (simulated, interoperable with NonceExchange)
- NonceDelin (simulated, interoperable with NonceExchange)

## Usage

Clone the repository and run `cargo run` (requires Rust compiler) which builds the project and runs the `mpcd` demonstration.

To view detailed log info, set environment variable `RUST_LOG=info`.

```bash
↪ RUST_LOG=info cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/mpcd`
[2021-05-12T09:28:58Z INFO  mpcd] Starting
[2021-05-12T09:28:58Z INFO  mpcd] Discovered reader Gemalto PC Twin Reader 00 00
[2021-05-12T09:28:58Z INFO  mpcd] Card connected
[2021-05-12T09:28:58Z INFO  mpcd::client::smartcard] Selecting applet mpcapplet
[2021-05-12T09:28:58Z INFO  mpcd::client::smartcard] Selected successfully
[2021-05-12T09:28:58Z INFO  mpcd] New client SHINE | ID 029f455a3c948733d270a3d2add145d6737e354263bc421daffce89d24efa53962
[2021-05-12T09:28:58Z INFO  mpcd] New client Simulator 0.1.0 | ID 0251b14c1558d98a8c6a859d8dfd414431a92f032503f9abf5da28e022a508afa5
[2021-05-12T09:28:58Z INFO  mpcd] New client Simulator 0.1.0 | ID 020511e9abbb8c6a110750a03e7de22f048560906cf2cde155d4915fb7d52c6329
[2021-05-12T09:29:17Z INFO  mpcd] Nonce exchange successful
[2021-05-12T09:29:26Z INFO  mpcd] Nonce caching successful
[2021-05-12T09:29:36Z INFO  mpcd] Key piggybacking successful
[2021-05-12T09:29:36Z WARN  mpcd] Some clients do not support nonce commitment - skipping
[2021-05-12T09:29:41Z INFO  mpcd] Interoperability with nonce commitment successful
[2021-05-12T09:29:41Z WARN  mpcd] Some clients do not support nonce delinearization - skipping
[2021-05-12T09:29:46Z INFO  mpcd] Interoperability with nonce delinearization successful
[2021-05-12T09:29:46Z INFO  mpcd] Terminating
```

If simulated clients are sufficient, conditional compilation without PC/SC backend can be performed with `--no-default-features` option.
