# Secp256k1

Elixir bindings for [secp256k1](https://github.com/bitcoin-core/secp256k1) library

Generated documentation can be found at https://secp256k1.sgiath.dev

## Installation

The package can be installed by adding `secp256k1` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:secp256k1, git: "https://git.sr.ht/~sgiath/secp256k1"}
  ]
end
```

During the compilation the C library is clonned and build from source. If you are having probem
compiling the library please refer to the original repository.

The C code wrapping the library is also build during the compilation. I only tested it on Linux
machine so if you are having problem compiling it on Mac or Windows it is most likely related to
that. Please fill an issue but I don't have other systems available to me so don't expect me to
fix it anytime soon (contributions are welcome though :) ).

## Features

- [x] generate secure random seckey
- [x] derive pubkey and serialize it in compressed, uncompressed or xonly format
- [x] generate and validate ECDSA signatures
- [x] generate and validate Schnorr signatures
- [x] compute Diffie-Hellman secret
