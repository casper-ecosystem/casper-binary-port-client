# casper-binary-port-client

A binary-port client library and CLI binary for interacting with the Casper network.

## Running the client

The client runs in one of several modes, each mode performing a single action. To see all available commands:

```
cargo run -- --release -- help
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
cargo run -- information block-header --help
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

## Examples of using the raw command

This repo contains a collection of files, which can be used to determine what are the error responses in case we provide a byte-level malformed request to the node. They reside in `resources/examples` and their interpretation is as follows:

- `keep_alive.bin` is a correct keep alive request, it should have an OK response
- `unsupported_request_tag.bin` this has a malformed `request_tag` value (255) which is not interpretable. Expected error code: `10`
- `invalid_protocol_version.bin` has `1.0.0` semver in protocol version which is unsupported. Expected error code: `6`
- `binary_body_doesnt_match_tag.bin` has a structurally valid header and body, bod the headers tag points to `Get`, while the body is a `KeepAlive` request body. Expected error code: `96`
- `invalid_binary_request_version.bin` has binary_protocol_version: 255 which is not suported. Expected error code: `61`
- `malformed_binary_header.bin` has not enough bytes to read a BinaryHeader. Expected error code: `95`
- `too_little_bytes_for_version.bin` has not enough bytes to read binary protocol version. Expected error code: `93`

These files can be used as follows:

```commandLine
cargo run -- --node-address 0.0.0.0:28101 raw --file-path ./resources/examples/keep_alive.bin --output-to-console true
```
