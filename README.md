# scroll-halo2-verifier

## Instructions for generating solidity code of a single "sample circuit"

Currently everything only works with no public inputs (so there is no instance column) in your circuit.

We remove the aggregation layer from Scroll's halo2 verifier. To setup:

- Add this repo to `Cargo.toml` for relevant packages
- Copy [this example](halo2-snark-aggregator-sdk/examples/simple-example.rs) to `main.rs` in the main repo with your halo2 circuits.
- Modify everything before [this line](halo2-snark-aggregator-sdk/examples/simple-example.rs#L328) to configure the circuit you want to test.
- Implement `Default` trait for `MyCircuit` so key generation does what you expect.
- Configure `TestCircuit` appropriately.
- Copy `templates` folder from [here](https://github.com/jonathanpwang/scroll-halo2-verifier/tree/main/halo2-snark-aggregator-solidity/templates) to the current root directory.
- We use the SDK to generate solidity code of the sample circuit: use command

```
cargo run --release -- --command verify_solidity
```

- To estimate gas cost, etc, see [readme](halo2-snark-aggregator-solidity/README.md).

(The other commands in SDK are not guaranteed to work due to read/write issues and because we stripped out aggregation layer.)
