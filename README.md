# Secp256k1 library

[![Hex.pm](https://img.shields.io/hexpm/v/lib_secp256k1.svg?style=flat&color=blue)](https://hex.pm/packages/lib_secp256k1)
[![Docs](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/lib_secp256k1)

Elixir bindings for the [secp256k1](https://github.com/bitcoin-core/secp256k1) cryptographic
library, used extensively in blockchain and cryptocurrency applications.

## Installation

Add `lib_secp256k1` to your project's dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:lib_secp256k1, "~> 0.6.0"},
  ]
end
```

The underlying C library and Elixir bindings are compiled automatically during the installation.
If you encounter issues during compilation, please check the original secp256k1 repository.

Currently, compilation is tested primarily on Linux. If you experience issues on macOS or Windows,
please open an issue—although immediate support for these platforms is limited, contributions are
always welcome.

### MacOS

You may need to install additional dependencies via Homebrew:

```
brew install make gcc autoconf autobuild
```

## Features

- [x] generate secure random seckey
- [x] derive pubkey and serialize it in compressed, uncompressed or xonly format
- [x] generate and validate ECDSA signatures
- [x] generate and validate Schnorr signatures
- [x] compute Diffie-Hellman secret
