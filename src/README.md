# Ethereum handshake example with possibility to use discovery 

Tool performing Ethereum handshake with a node.

It can use a provided enode or use a bootnode to discover nodes.

For discovery the default bootnode is the first one taken from Geth's MAINNET_BOOTNODES but can also use one provided via cli.

### How to use
First - build:

`cargo build --release`

Then:

- with locally hosted enode:
Preferabely using Geth or Reth:

For Geth:
```
wget wget https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-1.13.8-b20b4a71.tar.gz
tar xvf geth-linux-amd64-1.13.8-b20b4a71.tar.gz
cd tar xvf geth-linux-amd64-1.13.8-b20b4a71
./geth
```

After a few seconds it should start. Find a line in the console output similar to:

`Started P2P networking                   self=enode://a963662828fb26fc7a5c0ad1a167efe69de6815b3230538dc6f3f0b964da12f833f261e8a819dea9f8eed5c308343b0ea4f2f97d7f385ea6fc356d08aba9495f@127.0.0.1:30303`

Then copy the enode url from the output.

Run the tool with the enode address copied
```
./target/release/shake-that-hand --enode enode://a963662828fb26fc7a5c0ad1a167efe69de6815b3230538dc6f3f0b964da12f833f261e8a819dea9f8eed5c308343b0ea4f2f97d7f385ea6fc356d08aba9495f@127.0.0.1:30303
```

The expected output should end with something similar to

`Handshake succeeded with Geth/v1.13.8-stable-b20b4a71/linux-amd64/go1.21.5`

- with discovery

```
./target/release/shake-that-hand --crawl
```

Once it finds a node with which it can finish the handshake then it should end with a line similar to 

`Handshake succeeded with Nethermind/v1.23.0+bcd3b8ae/linux-x64/dotnet7.0.14`

- with discovery and custom bootnode

```
./target/release/shake-that-hand --crawl --enode enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303
```

The output should end similarly to previous cases

### Known Issues

It doesn't always work. Seems like there is a bug that makes it randomly fail.

With locally hosted eth node it usually helps running the tool two or three times in a row.
With discovery it often helps to use a different bootnode or wait a few minutes befor retrying.

### Implementation based on:
- [devp2p rlpx](https://github.com/ethereum/devp2p/blob/master/rlpx.md)
- [devp2p discovery](https://github.com/ethereum/devp2p/blob/master/discv4.md)
- [Geth](https://github.com/ethereum/go-ethereum)
- [Reth](https://github.com/paradigmxyz/reth)

