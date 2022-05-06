# SHINE-mediator

`mediator` is a Rust implementation of a service that mediates communication among clients running different multi-party Schnorr signature protocol implementations. `mediator` can interact with smartcards running SHINE applet via PC/SC interface and contains internal implementations of other multi-party Schnorr signature protocols.

## Supported protocols

Currently, `mediator` supports distributed key generation with commitment and multiple approaches to Schnorr signing.

### Key Generation

- KeygenCommit (smartcard, simulated)

### Schnorr Signing

- NonceExchange (smartcard, simulated)
- NonceCommit (simulated, interoperable with NonceExchange)
- NonceDelin (simulated, interoperable with NonceExchange)

## Usage

Clone the repository and run `cargo run -- --test` (requires Rust compiler) which builds the project and runs `mediator` functionality tests.

To view detailed log info, set environment variable `RUST_LOG=info`.

```bash
↪ RUST_LOG=info cargo run -- --test
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/mediator`
[2021-05-12T09:28:58Z INFO  mediator] Starting
[2021-05-12T09:28:58Z INFO  mediator] Discovered reader Gemalto PC Twin Reader 00 00
[2021-05-12T09:28:58Z INFO  mediator] Card connected
[2021-05-12T09:28:58Z INFO  mediator::client::smartcard] Selecting applet mpcapplet
[2021-05-12T09:28:58Z INFO  mediator::client::smartcard] Selected successfully
[2021-05-12T09:28:58Z INFO  mediator] New client SHINE | ID 029f455a3c948733d270a3d2add145d6737e354263bc421daffce89d24efa53962
[2021-05-12T09:28:58Z INFO  mediator] New client Simulator 0.1.0 | ID 0251b14c1558d98a8c6a859d8dfd414431a92f032503f9abf5da28e022a508afa5
[2021-05-12T09:28:58Z INFO  mediator] New client Simulator 0.1.0 | ID 020511e9abbb8c6a110750a03e7de22f048560906cf2cde155d4915fb7d52c6329
[2021-05-12T09:29:17Z INFO  mediator] Nonce exchange successful
[2021-05-12T09:29:26Z INFO  mediator] Nonce caching successful
[2021-05-12T09:29:36Z INFO  mediator] Key piggybacking successful
[2021-05-12T09:29:36Z WARN  mediator] Some clients do not support nonce commitment - skipping
[2021-05-12T09:29:41Z INFO  mediator] Interoperability with nonce commitment successful
[2021-05-12T09:29:41Z WARN  mediator] Some clients do not support nonce delinearization - skipping
[2021-05-12T09:29:46Z INFO  mediator] Interoperability with nonce delinearization successful
[2021-05-12T09:29:46Z INFO  mediator] Terminating
```

If simulated clients are sufficient, conditional compilation without PC/SC backend can be performed with `--no-default-features` option.
