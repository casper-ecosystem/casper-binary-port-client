# casper-binary-port-client

A binary-port client library and CLI binary for interacting with the Casper network.

## Running the client

The client runs in one of several modes, each mode performing a single action. To see all available commands:

```
cargo run --release -- help
```

<details><summary>example output</summary>

```commandLine
A CLI binary for interacting with the Casper network via the binary protocol

Usage: casper-binary-port-client [OPTIONS] --node-address <NODE_ADDRESS> <COMMAND>

Commands:
  information                Send information request of a given kind
  record                     Send record request with a given ID and key
  state                      Retrieves data from the global state
  try-accept-transaction     Sends a transaction to the network for inclusion
  try-speculative-execution  Sends a transaction to the network for speculative execution
  help                       Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose                      Provides a verbose output as the command is being handled (not supported yet)
  -n, --node-address <NODE_ADDRESS>
  -h, --help                         Print help
```

</details>

To get further info on any command, run `help` followed by the subcommand, e.g.

```
cargo run information block-header --help
```

<details><summary>example output</summary>

```commandLine
Retrieve block header by height or hash

Usage: casper-binary-port-client information block-header [OPTIONS]

Options:
      --hash <HASH>
      --height <HEIGHT>
  -h, --help             Print help
```

</details>

## Client library

The `binary-port-access` directory contains source for the client library, which may be called directly rather than through the CLI binary. The CLI app `casper-binary-port-client` makes use of this library to implement its functionality.

## License

Licensed under the [Apache License Version 2.0](LICENSE).
